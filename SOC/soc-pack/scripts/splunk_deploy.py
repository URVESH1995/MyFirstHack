#!/usr/bin/env python3
"""
splunk_deploy.py — deploy correlation searches and lookups to Splunk Cloud via REST,
plus backtest a search before you enable it.

WHY THIS EXISTS
Splunk Cloud has no filesystem access, so you cannot drop savedsearches.conf into
an app directory. Your three options are a vetted private app, the ES Content
Management UI, or the REST API. This script does the REST option, which is the one
that fits version control and CI/CD.

PREREQUISITES
-------------
1. Management port access. On Splunk Cloud, port 8089 is reachable at
   https://<stack>.splunkcloud.com:8089 but your source IP usually has to be in
   the stack's IP allow list. Check: Splunk Cloud Admin Console -> IP allow list ->
   Splunk Management Port. If this script times out, that's almost always why.
2. An authentication token: Settings -> Tokens -> New Token. Prefer this over
   username/password.
3. A role with edit_search_schedule, edit_correlationsearches (for ES),
   and admin_all_objects or equivalent on the target app.

  export SPLUNK_HOST="yourstack.splunkcloud.com"
  export SPLUNK_TOKEN="eyJ..."
  # optional:
  export SPLUNK_PORT="8089"
  export SPLUNK_APP="SplunkEnterpriseSecuritySuite"

USAGE
-----
  # ALWAYS backtest first. The runbooks ship every search disabled for a reason.
  ./splunk_deploy.py backtest --conf savedsearches.conf --earliest -7d

  # Deploy everything, still disabled, so you can enable one at a time
  ./splunk_deploy.py deploy --conf savedsearches.conf

  # Deploy and enable a single search after you've tuned it
  ./splunk_deploy.py deploy --conf savedsearches.conf \
      --only "Access - Password Spray Against Multiple Accounts - Rule" --enable

  ./splunk_deploy.py list
  ./splunk_deploy.py enable  --name "Access - Password Spray Against Multiple Accounts - Rule"
  ./splunk_deploy.py disable --name "..."
  ./splunk_deploy.py upload-lookup --file lookups/rmm_tools.csv
  ./splunk_deploy.py delete  --name "..."      # prompts

BACKTEST OUTPUT — how to read it
  events/day   0        -> the search may be broken, or your data doesn't match the
                           index/sourcetype assumptions. Investigate before assuming
                           "no threats". A silent rule is worse than a noisy one.
  events/day   1-20     -> good. Enable.
  events/day   21-100   -> needs tuning. Populate the lookups first.
  events/day   >100     -> do not enable. It will train analysts to ignore the queue.
"""

import argparse
import csv
import io
import os
import sys
import time
import urllib3

try:
    import requests
except ImportError:
    sys.exit("pip install requests")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HOST = os.environ.get("SPLUNK_HOST", "")
PORT = os.environ.get("SPLUNK_PORT", "8089")
APP = os.environ.get("SPLUNK_APP", "SplunkEnterpriseSecuritySuite")
TOKEN = os.environ.get("SPLUNK_TOKEN", "")
VERIFY = os.environ.get("SPLUNK_VERIFY_TLS", "true").lower() != "false"

# Keys we forward to the saved/searches endpoint. Anything else in the conf
# stanza is ignored with a warning, so a typo doesn't silently do nothing.
ALLOWED_KEYS = {
    "search", "description", "cron_schedule", "dispatch.earliest_time",
    "dispatch.latest_time", "enableSched", "disabled", "schedule_window",
    "alert.digest_mode", "alert.suppress", "alert.suppress.fields",
    "alert.suppress.period", "alert.severity", "alert_type", "alert_comparator",
    "alert_threshold", "counttype", "quantity", "relation",
    "action.correlationsearch.enabled", "action.correlationsearch.label",
    "action.correlationsearch.annotations",
    "action.notable", "action.notable.param.rule_title",
    "action.notable.param.rule_description", "action.notable.param.security_domain",
    "action.notable.param.severity", "action.notable.param.nes_fields",
    "action.notable.param.default_owner", "action.notable.param.default_status",
    "action.notable.param.drilldown_name", "action.notable.param.drilldown_search",
    "action.notable.param.drilldown_earliest_offset",
    "action.notable.param.drilldown_latest_offset",
    "action.risk", "action.risk.param._risk", "action.risk.param._risk_message",
    "action.risk.param.verbose",
    "request.ui_dispatch_app", "request.ui_dispatch_view",
    "is_scheduled", "realtime_schedule",
}


def _base():
    if not HOST:
        sys.exit("Set SPLUNK_HOST (e.g. yourstack.splunkcloud.com)")
    if not TOKEN:
        sys.exit("Set SPLUNK_TOKEN (Settings -> Tokens -> New Token)")
    return f"https://{HOST}:{PORT}"


def _headers():
    return {"Authorization": f"Bearer {TOKEN}"}


def _req(method, path, data=None, params=None, files=None, timeout=120):
    url = f"{_base()}{path}"
    try:
        r = requests.request(method, url, headers=_headers(), data=data,
                             params=params, files=files, verify=VERIFY,
                             timeout=timeout)
    except requests.exceptions.ConnectTimeout:
        sys.exit(f"Connection to {HOST}:{PORT} timed out.\n"
                 f"On Splunk Cloud this is almost always the IP allow list for the "
                 f"management port. Admin Console -> IP allow list -> "
                 f"Splunk Management Port.")
    except requests.exceptions.SSLError as e:
        sys.exit(f"TLS error: {e}\nIf using a self-signed cert, set "
                 f"SPLUNK_VERIFY_TLS=false (lab only).")
    return r


def parse_conf(path):
    """Parse a Splunk .conf file.

    Do not use configparser here. Splunk marks line continuation with a
    trailing backslash at column 0, whereas configparser expects indentation.
    Feeding a real savedsearches.conf to configparser raises an AttributeError
    partway through and silently mangles the SPL before it does.
    """
    if not os.path.isfile(path):
        sys.exit(f"No such file: {path}")

    with open(path, encoding="utf-8") as fh:
        raw_lines = fh.read().split("\n")

    # 1. Join backslash continuations into single logical lines.
    joined, buf = [], None
    for line in raw_lines:
        line = line.rstrip("\r")
        buf = line if buf is None else buf + "\n" + line
        if buf.endswith("\\"):
            buf = buf[:-1]
            continue
        joined.append(buf)
        buf = None
    if buf is not None:
        joined.append(buf)

    # 2. Parse [stanza] / key = value.
    stanzas, current, last_key = {}, None, None
    for line in joined:
        stripped = line.strip()
        if not stripped or stripped[0] in "#;":
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            current = stripped[1:-1]
            stanzas[current] = {}
            last_key = None
            continue
        if current is None:
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            stanzas[current][k.strip()] = v.strip()
            last_key = k.strip()
        elif last_key:
            # Wrapped value with no backslash — append rather than drop it.
            stanzas[current][last_key] += "\n" + stripped
    return stanzas


def deploy(a):
    stanzas = parse_conf(a.conf)
    names = [a.only] if a.only else list(stanzas)
    if a.only and a.only not in stanzas:
        sys.exit(f"Stanza not found in {a.conf}: {a.only}\n"
                 f"Available:\n  " + "\n  ".join(stanzas))

    print(f"Deploying {len(names)} search(es) to app '{APP}' on {HOST}\n")
    for name in names:
        stanza = stanzas[name]
        if "search" not in stanza:
            print(f"  SKIP  {name} — no 'search' key")
            continue

        payload = {"name": name}
        for k, v in stanza.items():
            if k in ALLOWED_KEYS:
                payload[k] = v
            else:
                print(f"        note: ignoring unrecognised key '{k}'")

        # Ship disabled by default, per the runbook guidance.
        payload["disabled"] = "0" if a.enable else "1"
        if a.enable:
            payload["enableSched"] = "1"

        path = f"/servicesNS/nobody/{APP}/saved/searches"
        r = _req("POST", path, data=payload)

        if r.status_code in (200, 201):
            state = "ENABLED" if a.enable else "disabled"
            print(f"  OK    {name}  ({state})")
        elif r.status_code == 409:
            # Already exists — update it in place.
            upd = {k: v for k, v in payload.items() if k != "name"}
            r2 = _req("POST", f"{path}/{requests.utils.quote(name, safe='')}", data=upd)
            if r2.status_code in (200, 201):
                state = "ENABLED" if a.enable else "disabled"
                print(f"  UPD   {name}  ({state})")
            else:
                print(f"  FAIL  {name} [update {r2.status_code}] {r2.text[:200]}")
        else:
            print(f"  FAIL  {name} [{r.status_code}] {r.text[:300]}")
    print("\nReminder: searches deployed disabled. Backtest, tune, then enable "
          "one at a time and watch for five business days.")


def backtest(a):
    """Run each search over a historical window and report volume."""
    stanzas = parse_conf(a.conf)
    names = [a.only] if a.only else list(stanzas)
    print(f"Backtesting {len(names)} search(es) over {a.earliest} -> now\n")
    print(f"{'events':>8}  {'per day':>8}  {'verdict':<22}  search")
    print("-" * 100)

    for name in names:
        spl = stanzas[name].get("search")
        if not spl:
            continue
        if not spl.lstrip().startswith("|"):
            spl = "search " + spl

        r = _req("POST", f"/servicesNS/nobody/{APP}/search/jobs",
                 data={"search": spl, "earliest_time": a.earliest,
                       "latest_time": "now", "exec_mode": "blocking",
                       "output_mode": "json", "timeout": 900},
                 timeout=960)
        if r.status_code not in (200, 201):
            print(f"{'ERR':>8}  {'':>8}  {'dispatch failed':<22}  {name}")
            print(f"          {r.text[:200]}")
            continue

        try:
            sid = r.json().get("sid")
        except ValueError:
            import re
            m = re.search(r"<sid>(.*?)</sid>", r.text)
            sid = m.group(1) if m else None
        if not sid:
            print(f"{'ERR':>8}  {'':>8}  {'no sid returned':<22}  {name}")
            continue

        rr = _req("GET", f"/servicesNS/nobody/{APP}/search/jobs/{sid}/results",
                  params={"output_mode": "json", "count": 0})
        try:
            count = len(rr.json().get("results", []))
        except ValueError:
            count = -1

        days = _window_days(a.earliest)
        per_day = round(count / days, 1) if days else count

        if count < 0:
            verdict = "could not parse"
        elif count == 0:
            verdict = "ZERO - verify data"
        elif per_day <= 20:
            verdict = "OK - enable"
        elif per_day <= 100:
            verdict = "TUNE FIRST"
        else:
            verdict = "DO NOT ENABLE"

        print(f"{count:>8}  {per_day:>8}  {verdict:<22}  {name}")

    print("\nZERO results usually means the index/sourcetype assumptions don't match "
          "your environment, not that you have no threats. Check with:\n"
          "  | tstats count where index=* by index, sourcetype")


def _window_days(earliest):
    e = earliest.strip().lstrip("-").rstrip("@dhm")
    try:
        n = float("".join(c for c in e if c.isdigit() or c == "."))
    except ValueError:
        return 1
    if earliest.endswith(("d", "d@d")) or "d" in earliest:
        return max(n, 0.04)
    if "h" in earliest:
        return max(n / 24, 0.04)
    return max(n, 0.04)


def list_searches(a):
    r = _req("GET", f"/servicesNS/nobody/{APP}/saved/searches",
             params={"output_mode": "json", "count": 0,
                     "search": a.filter or ""})
    if r.status_code != 200:
        sys.exit(f"List failed [{r.status_code}]: {r.text[:300]}")
    entries = r.json().get("entry", [])
    print(f"{'sched':<6} {'disabled':<9} {'cron':<16} name")
    print("-" * 100)
    for e in entries:
        c = e.get("content", {})
        if a.correlation_only and str(c.get("action.correlationsearch.enabled")) != "1":
            continue
        print(f"{str(c.get('is_scheduled')):<6} {str(c.get('disabled')):<9} "
              f"{str(c.get('cron_schedule'))[:15]:<16} {e.get('name')}")


def toggle(a, disabled):
    name = requests.utils.quote(a.name, safe="")
    r = _req("POST", f"/servicesNS/nobody/{APP}/saved/searches/{name}",
             data={"disabled": "1" if disabled else "0",
                   "enableSched": "0" if disabled else "1"})
    if r.status_code in (200, 201):
        print(f"{'Disabled' if disabled else 'Enabled'}: {a.name}")
    else:
        sys.exit(f"Failed [{r.status_code}]: {r.text[:300]}")


def delete(a):
    if input(f"Delete saved search '{a.name}'? Type DELETE to confirm: ").strip() != "DELETE":
        sys.exit("Aborted.")
    name = requests.utils.quote(a.name, safe="")
    r = _req("DELETE", f"/servicesNS/nobody/{APP}/saved/searches/{name}")
    print("Deleted." if r.status_code in (200, 201)
          else f"Failed [{r.status_code}]: {r.text[:300]}")


def upload_lookup(a):
    if not os.path.isfile(a.file):
        sys.exit(f"No such file: {a.file}")
    fname = os.path.basename(a.file)

    # Validate it parses as CSV and has a header — a malformed lookup silently
    # breaks every search that references it.
    with open(a.file, newline="", encoding="utf-8") as fh:
        rows = list(csv.reader(fh))
    if len(rows) < 1 or not rows[0]:
        sys.exit(f"{fname} has no header row.")
    print(f"{fname}: {len(rows)-1} data rows, columns: {', '.join(rows[0])}")

    with open(a.file, "rb") as fh:
        r = _req("POST", f"/servicesNS/nobody/{APP}/data/lookup-table-files",
                 data={"name": fname},
                 files={"eventlog": (fname, fh.read(), "text/csv")})
    if r.status_code in (200, 201):
        print(f"Uploaded lookup: {fname}")
    elif r.status_code == 409:
        print(f"{fname} already exists. Replace it via Settings -> Lookups -> "
              f"Lookup table files, or delete it first.")
    else:
        print(f"Failed [{r.status_code}]: {r.text[:400]}")


def main():
    p = argparse.ArgumentParser(description="Splunk Cloud correlation search deployment")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("deploy")
    s.add_argument("--conf", required=True)
    s.add_argument("--only", help="deploy a single stanza by exact name")
    s.add_argument("--enable", action="store_true",
                   help="enable on deploy — only after backtesting")
    s.set_defaults(func=deploy)

    s = sub.add_parser("backtest")
    s.add_argument("--conf", required=True)
    s.add_argument("--only")
    s.add_argument("--earliest", default="-7d")
    s.set_defaults(func=backtest)

    s = sub.add_parser("list")
    s.add_argument("--filter", default="")
    s.add_argument("--correlation-only", action="store_true")
    s.set_defaults(func=list_searches)

    s = sub.add_parser("enable")
    s.add_argument("--name", required=True)
    s.set_defaults(func=lambda a: toggle(a, False))

    s = sub.add_parser("disable")
    s.add_argument("--name", required=True)
    s.set_defaults(func=lambda a: toggle(a, True))

    s = sub.add_parser("delete")
    s.add_argument("--name", required=True)
    s.set_defaults(func=delete)

    s = sub.add_parser("upload-lookup")
    s.add_argument("--file", required=True)
    s.set_defaults(func=upload_lookup)

    a = p.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
