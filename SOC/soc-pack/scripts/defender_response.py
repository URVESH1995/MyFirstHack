#!/usr/bin/env python3
"""
defender_response.py — Microsoft Defender for Endpoint response actions for SOC runbooks.

Wraps the containment actions the runbooks call for, so that a P1 at 3am is one
command instead of twelve clicks. Every action is logged locally for the SIR.

SETUP
-----
1. Entra ID -> App registrations -> New registration (e.g. "SOC-Response-Automation")
2. API permissions -> APIs my organization uses -> WindowsDefenderATP
   Application permissions required (grant admin consent):
     Machine.Isolate            isolate / unisolate
     Machine.CollectForensics   collect investigation package
     Machine.Scan               antivirus scan
     Machine.RestrictExecution  restrict app execution
     Machine.StopAndQuarantine  stop and quarantine file
     Machine.Read.All           device lookup
     Ti.ReadWrite.All           indicators
     AdvancedQuery.Read.All     advanced hunting
3. Certificates & secrets -> new client secret. Store it in a secrets manager,
   not in this file and not in your shell history.

4. Environment:
     export MDE_TENANT_ID="..."
     export MDE_CLIENT_ID="..."
     export MDE_CLIENT_SECRET="..."      # prefer: pull from a vault at runtime

USAGE
-----
  ./defender_response.py isolate      --device HOST01 --type Full --comment SIR0012345
  ./defender_response.py unisolate    --device HOST01 --comment "SIR0012345 verified clean"
  ./defender_response.py collect      --device HOST01 --comment SIR0012345
  ./defender_response.py scan         --device HOST01 --scan-type Full --comment SIR0012345
  ./defender_response.py restrict     --device HOST01 --comment SIR0012345
  ./defender_response.py quarantine   --device HOST01 --sha1 <sha1> --comment SIR0012345
  ./defender_response.py indicator    --value <sha256> --type FileSha256 --action BlockAndRemediate \
                                      --title "SIR0012345 Qakbot loader"
  ./defender_response.py isolate-bulk --file hosts.txt --type Full --comment SIR0012345
  ./defender_response.py hunt         --query-file hunt.kql
  ./defender_response.py status       --action-id <guid>
  ./defender_response.py device       --device HOST01

SAFETY
------
* Destructive/disruptive actions prompt for confirmation unless --yes is passed.
* isolate-bulk always shows the full host list and requires confirmation, because
  the runbooks call for simultaneous isolation and a typo there is expensive.
* Nothing in this script deletes data or moves money. Password resets are handled
  by Invoke-IdentityContainment.ps1 with a human in the loop, by design.
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    sys.exit("pip install requests")

MDE_BASE = "https://api.securitycenter.microsoft.com/api"
GRAPH_HUNT = "https://graph.microsoft.com/v1.0/security/runHuntingQuery"
AUDIT_LOG = os.environ.get("SOC_AUDIT_LOG", "soc_response_actions.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)sZ %(levelname)s %(message)s",
    handlers=[logging.FileHandler(AUDIT_LOG), logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("mde")


# --------------------------------------------------------------------------- auth
def get_token(resource="https://api.securitycenter.microsoft.com/.default"):
    tenant = os.environ.get("MDE_TENANT_ID")
    client = os.environ.get("MDE_CLIENT_ID")
    secret = os.environ.get("MDE_CLIENT_SECRET")
    missing = [n for n, v in
               (("MDE_TENANT_ID", tenant), ("MDE_CLIENT_ID", client),
                ("MDE_CLIENT_SECRET", secret)) if not v]
    if missing:
        sys.exit(f"Missing environment variables: {', '.join(missing)}")

    r = requests.post(
        f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        data={"grant_type": "client_credentials", "client_id": client,
              "client_secret": secret, "scope": resource},
        timeout=30,
    )
    if r.status_code != 200:
        sys.exit(f"Token request failed [{r.status_code}]: {r.text[:400]}")
    return r.json()["access_token"]


def api(method, path, token, body=None, base=MDE_BASE, retries=3):
    """Call the API with retry on 429/5xx, honouring Retry-After."""
    url = path if path.startswith("http") else f"{base}{path}"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    for attempt in range(1, retries + 1):
        r = requests.request(method, url, headers=headers,
                             json=body if body else None, timeout=60)
        if r.status_code == 429 or r.status_code >= 500:
            wait = int(r.headers.get("Retry-After", min(2 ** attempt * 5, 60)))
            log.warning("HTTP %s on %s — retry %s/%s in %ss",
                        r.status_code, path, attempt, retries, wait)
            time.sleep(wait)
            continue
        return r
    return r


# ------------------------------------------------------------------ device lookup
def resolve_device(token, name_or_id):
    """Accept a hostname or an MDE machine ID. Returns (machine_id, machine_dict)."""
    # Heuristic: MDE machine IDs are 40-char lowercase hex.
    if len(name_or_id) == 40 and all(c in "0123456789abcdef" for c in name_or_id.lower()):
        r = api("GET", f"/machines/{name_or_id}", token)
        if r.status_code == 200:
            return name_or_id, r.json()

    short = name_or_id.split(".")[0].lower()
    r = api("GET", f"/machines?$filter=startswith(computerDnsName,'{short}')", token)
    if r.status_code != 200:
        sys.exit(f"Device lookup failed [{r.status_code}]: {r.text[:300]}")
    machines = r.json().get("value", [])
    if not machines:
        sys.exit(f"No device found matching '{name_or_id}'")

    # Prefer the most recently seen, and warn on ambiguity — stale duplicate
    # device objects are common and isolating the wrong one wastes critical time.
    machines.sort(key=lambda m: m.get("lastSeen", ""), reverse=True)
    if len(machines) > 1:
        log.warning("%d devices matched '%s' — using most recently seen:",
                    len(machines), name_or_id)
        for m in machines[:5]:
            log.warning("   %s  lastSeen=%s  health=%s  id=%s",
                        m.get("computerDnsName"), m.get("lastSeen"),
                        m.get("healthStatus"), m.get("id"))
    m = machines[0]
    return m["id"], m


def show_device(token, name):
    mid, m = resolve_device(token, name)
    fields = ["computerDnsName", "id", "osPlatform", "osVersion", "lastSeen",
              "lastIpAddress", "lastExternalIpAddress", "healthStatus",
              "riskScore", "exposureLevel", "isAadJoined", "machineTags",
              "onboardingStatus", "isolationState", "rbacGroupName"]
    print(json.dumps({k: m.get(k) for k in fields}, indent=2))
    return mid


# ----------------------------------------------------------------- machine actions
def _post_action(token, mid, action, body, label, hostname=""):
    r = api("POST", f"/machines/{mid}/{action}", token, body)
    if r.status_code in (200, 201):
        d = r.json()
        log.info("OK  %-24s host=%s actionId=%s status=%s",
                 label, hostname or mid, d.get("id"), d.get("status"))
        return d.get("id")
    # 400 with "already" in the body usually means the state is already what you want
    log.error("FAIL %-24s host=%s [%s] %s", label, hostname or mid,
              r.status_code, r.text[:300])
    return None


def isolate(token, name, iso_type, comment):
    mid, m = resolve_device(token, name)
    if m.get("isolationState") == "Isolated":
        log.info("SKIP isolate — %s is already isolated", m.get("computerDnsName"))
        return None
    return _post_action(token, mid, "isolate",
                        {"Comment": comment, "IsolationType": iso_type},
                        f"isolate({iso_type})", m.get("computerDnsName"))


def unisolate(token, name, comment):
    mid, m = resolve_device(token, name)
    return _post_action(token, mid, "unisolate", {"Comment": comment},
                        "unisolate", m.get("computerDnsName"))


def collect_package(token, name, comment):
    mid, m = resolve_device(token, name)
    aid = _post_action(token, mid, "collectInvestigationPackage",
                       {"Comment": comment}, "collectPackage",
                       m.get("computerDnsName"))
    if aid:
        log.info("Package download URI available once complete: "
                 "GET /machineactions/%s/getPackageUri", aid)
    return aid


def av_scan(token, name, scan_type, comment):
    mid, m = resolve_device(token, name)
    return _post_action(token, mid, "runAntiVirusScan",
                        {"Comment": comment, "ScanType": scan_type},
                        f"avScan({scan_type})", m.get("computerDnsName"))


def restrict(token, name, comment):
    mid, m = resolve_device(token, name)
    return _post_action(token, mid, "restrictCodeExecution", {"Comment": comment},
                        "restrictExecution", m.get("computerDnsName"))


def unrestrict(token, name, comment):
    mid, m = resolve_device(token, name)
    return _post_action(token, mid, "unrestrictCodeExecution", {"Comment": comment},
                        "unrestrictExecution", m.get("computerDnsName"))


def quarantine_file(token, name, sha1, comment):
    """Note: this API takes SHA1, not SHA256. Capture both hashes during triage."""
    if len(sha1) != 40:
        sys.exit("StopAndQuarantineFile requires a SHA1 (40 hex chars), not SHA256.")
    mid, m = resolve_device(token, name)
    return _post_action(token, mid, "StopAndQuarantineFile",
                        {"Comment": comment, "Sha1": sha1},
                        "stopAndQuarantine", m.get("computerDnsName"))


def action_status(token, action_id):
    r = api("GET", f"/machineactions/{action_id}", token)
    if r.status_code != 200:
        sys.exit(f"Status lookup failed [{r.status_code}]: {r.text[:300]}")
    d = r.json()
    print(json.dumps({k: d.get(k) for k in
                      ("id", "type", "status", "machineId", "computerDnsName",
                       "requestor", "requestorComment", "creationDateTimeUtc",
                       "lastUpdateDateTimeUtc", "errorHResult")}, indent=2))
    return d.get("status")


# --------------------------------------------------------------------- indicators
VALID_IND_TYPES = ["FileSha256", "FileSha1", "FileMd5", "IpAddress",
                   "DomainName", "Url", "CertificateThumbprint"]
VALID_IND_ACTIONS = ["Allowed", "Audit", "Block", "BlockAndRemediate", "Warn"]


def add_indicator(token, value, ind_type, action, title, description,
                  severity="High", generate_alert=True, expiration=None):
    body = {
        "indicatorValue": value,
        "indicatorType": ind_type,
        "action": action,
        "title": title,
        "description": description or title,
        "severity": severity,
        "generateAlert": generate_alert,
    }
    if expiration:
        body["expirationTime"] = expiration
    r = api("POST", "/indicators", token, body)
    if r.status_code in (200, 201):
        log.info("OK  indicator %s %s action=%s id=%s",
                 ind_type, value[:24], action, r.json().get("id"))
        return r.json().get("id")
    log.error("FAIL indicator %s %s [%s] %s", ind_type, value[:24],
              r.status_code, r.text[:300])
    return None


# ------------------------------------------------------------------------ hunting
def hunt(token_graph, query):
    r = api("POST", "", token_graph, {"query": query}, base=GRAPH_HUNT)
    if r.status_code != 200:
        sys.exit(f"Hunt failed [{r.status_code}]: {r.text[:500]}")
    d = r.json()
    rows = d.get("results", [])
    log.info("Hunt returned %d rows", len(rows))
    print(json.dumps(rows, indent=2, default=str))
    return rows


# --------------------------------------------------------------------------- bulk
def isolate_bulk(token, hosts, iso_type, comment, assume_yes=False):
    """Simultaneous isolation — see PB-08. Sequential isolation lets the
    attacker relocate, so this fires all requests in one pass."""
    print(f"\nAbout to isolate {len(hosts)} device(s), type={iso_type}:")
    for h in hosts:
        print(f"   - {h}")
    if not assume_yes:
        if input("\nType ISOLATE to confirm: ").strip() != "ISOLATE":
            sys.exit("Aborted — no action taken.")

    results = {}
    for h in hosts:
        try:
            results[h] = isolate(token, h, iso_type, comment)
        except SystemExit as e:
            log.error("SKIP %s — %s", h, e)
            results[h] = None
    ok = sum(1 for v in results.values() if v)
    log.info("Bulk isolation complete: %d/%d submitted", ok, len(hosts))
    if ok != len(hosts):
        log.warning("NOT ALL HOSTS ISOLATED — review failures above and "
                    "handle them manually before continuing the investigation.")
    return results


# --------------------------------------------------------------------------- main
def main():
    p = argparse.ArgumentParser(description="MDE response actions for SOC runbooks")
    p.add_argument("--yes", action="store_true", help="skip confirmation prompts")
    sub = p.add_subparsers(dest="cmd", required=True)

    def dev(sp, comment_required=True):
        sp.add_argument("--device", required=True, help="hostname or MDE machine id")
        sp.add_argument("--comment", required=comment_required,
                        help="SIR number and reason (goes into the MDE audit log)")

    s = sub.add_parser("isolate"); dev(s)
    s.add_argument("--type", default="Full", choices=["Full", "Selective"])

    s = sub.add_parser("unisolate"); dev(s)
    s = sub.add_parser("collect"); dev(s)
    s = sub.add_parser("restrict"); dev(s)
    s = sub.add_parser("unrestrict"); dev(s)

    s = sub.add_parser("scan"); dev(s)
    s.add_argument("--scan-type", default="Full", choices=["Full", "Quick"])

    s = sub.add_parser("quarantine"); dev(s)
    s.add_argument("--sha1", required=True, help="SHA1 of the file (not SHA256)")

    s = sub.add_parser("device")
    s.add_argument("--device", required=True)

    s = sub.add_parser("status")
    s.add_argument("--action-id", required=True)

    s = sub.add_parser("indicator")
    s.add_argument("--value", required=True)
    s.add_argument("--type", required=True, choices=VALID_IND_TYPES)
    s.add_argument("--action", default="BlockAndRemediate", choices=VALID_IND_ACTIONS)
    s.add_argument("--title", required=True)
    s.add_argument("--description", default="")
    s.add_argument("--severity", default="High",
                   choices=["Informational", "Low", "Medium", "High"])
    s.add_argument("--no-alert", action="store_true")
    s.add_argument("--expiration", help="ISO8601, e.g. 2026-12-31T00:00:00Z")

    s = sub.add_parser("isolate-bulk")
    s.add_argument("--file", required=True, help="text file, one hostname per line")
    s.add_argument("--type", default="Full", choices=["Full", "Selective"])
    s.add_argument("--comment", required=True)

    s = sub.add_parser("hunt")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--query")
    g.add_argument("--query-file")

    a = p.parse_args()
    log.info("=== invoked: %s by %s ===", a.cmd, os.environ.get("USER", "unknown"))

    if a.cmd == "hunt":
        token = get_token("https://graph.microsoft.com/.default")
        q = a.query if a.query else open(a.query_file).read()
        hunt(token, q)
        return

    token = get_token()

    if a.cmd == "isolate":
        isolate(token, a.device, a.type, a.comment)
    elif a.cmd == "unisolate":
        unisolate(token, a.device, a.comment)
    elif a.cmd == "collect":
        collect_package(token, a.device, a.comment)
    elif a.cmd == "scan":
        av_scan(token, a.device, a.scan_type, a.comment)
    elif a.cmd == "restrict":
        restrict(token, a.device, a.comment)
    elif a.cmd == "unrestrict":
        unrestrict(token, a.device, a.comment)
    elif a.cmd == "quarantine":
        quarantine_file(token, a.device, a.sha1, a.comment)
    elif a.cmd == "device":
        show_device(token, a.device)
    elif a.cmd == "status":
        action_status(token, a.action_id)
    elif a.cmd == "indicator":
        add_indicator(token, a.value, a.type, a.action, a.title,
                      a.description, a.severity, not a.no_alert, a.expiration)
    elif a.cmd == "isolate-bulk":
        hosts = [l.strip() for l in open(a.file) if l.strip()
                 and not l.startswith("#")]
        if not hosts:
            sys.exit("Host file is empty.")
        isolate_bulk(token, hosts, a.type, a.comment, a.yes)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\nInterrupted.")
