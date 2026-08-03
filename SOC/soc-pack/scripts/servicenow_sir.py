#!/usr/bin/env python3
"""
servicenow_sir.py — create and maintain Security Incident Response (SIR) records.

Purpose: make the "log every action with a UTC timestamp" rule cheap enough that
analysts actually do it. If it isn't in the ticket, it didn't happen.

SETUP
-----
  export SN_INSTANCE="yourinstance.service-now.com"
  export SN_USER="svc_soc_automation"
  export SN_PASSWORD="..."            # or use SN_OAUTH_TOKEN
  # optional:
  export SN_TABLE="sn_si_incident"    # default; use 'incident' if you don't have SecOps

The service account needs the sn_si.analyst role (or equivalent) plus read/write
on the SIR table and the attachment API.

IMPORTANT — STATE VALUES ARE INSTANCE-SPECIFIC
The numeric state values below are the out-of-box ServiceNow SIR defaults.
They are very commonly customized. VERIFY AGAINST YOUR INSTANCE before relying
on them:
    /sys_choice_list.do?sysparm_query=name=sn_si_incident^element=state
or:  ./servicenow_sir.py states
Then correct the STATES dict below.

USAGE
-----
  ./servicenow_sir.py create --title "Phishing campaign - 12 inboxes" \
      --description "$(cat notes.txt)" --category Phishing --impact 2 --urgency 2

  ./servicenow_sir.py note   --number SIR0012345 --text "Isolated HOST01 via MDE. Action id abc123."
  ./servicenow_sir.py state  --number SIR0012345 --to Contain
  ./servicenow_sir.py attach --number SIR0012345 --file evidence/rules.txt
  ./servicenow_sir.py get    --number SIR0012345
  ./servicenow_sir.py close  --number SIR0012345 --code "True Positive - Contained" \
      --notes "Vector: phishing. 12 delivered, 2 clicked, 1 credential compromise..."
  ./servicenow_sir.py states
"""

import argparse
import json
import mimetypes
import os
import sys
from datetime import datetime, timezone

try:
    import requests
    from requests.auth import HTTPBasicAuth
except ImportError:
    sys.exit("pip install requests")

INSTANCE = os.environ.get("SN_INSTANCE", "")
TABLE = os.environ.get("SN_TABLE", "sn_si_incident")

# Out-of-box SIR state values — VERIFY against your instance (see header).
STATES = {
    "Draft": 10,
    "Analysis": 16,
    "Contain": 18,
    "Eradicate": 19,
    "Recover": 20,
    "Review": 100,
    "Closed": 3,
    "Cancelled": 7,
}


def _auth():
    if not INSTANCE:
        sys.exit("Set SN_INSTANCE (e.g. yourinstance.service-now.com)")
    token = os.environ.get("SN_OAUTH_TOKEN")
    if token:
        return None, {"Authorization": f"Bearer {token}"}
    user, pwd = os.environ.get("SN_USER"), os.environ.get("SN_PASSWORD")
    if not (user and pwd):
        sys.exit("Set SN_USER and SN_PASSWORD, or SN_OAUTH_TOKEN")
    return HTTPBasicAuth(user, pwd), {}


def _call(method, path, body=None, params=None, files=None, data=None):
    auth, extra = _auth()
    headers = {"Accept": "application/json", **extra}
    if body is not None:
        headers["Content-Type"] = "application/json"
    url = f"https://{INSTANCE}{path}"
    r = requests.request(method, url, auth=auth, headers=headers,
                         json=body, params=params, files=files, data=data,
                         timeout=60)
    if r.status_code >= 400:
        sys.exit(f"ServiceNow API error [{r.status_code}] {method} {path}\n{r.text[:800]}")
    if not r.content:
        return {}
    try:
        return r.json()
    except ValueError:
        return {"raw": r.text}


def _stamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def find(number):
    """Return the sys_id and record for a SIR number."""
    res = _call("GET", f"/api/now/table/{TABLE}",
                params={"sysparm_query": f"number={number}", "sysparm_limit": 1})
    rows = res.get("result", [])
    if not rows:
        sys.exit(f"{number} not found in table {TABLE}")
    return rows[0]["sys_id"], rows[0]


def create(a):
    body = {
        "short_description": a.title,
        "description": a.description or a.title,
        "category": a.category,
        "impact": str(a.impact),
        "urgency": str(a.urgency),
        "state": str(STATES.get(a.state, STATES["Analysis"])),
    }
    if a.subcategory:
        body["subcategory"] = a.subcategory
    if a.assignment_group:
        body["assignment_group"] = a.assignment_group
    if a.assigned_to:
        body["assigned_to"] = a.assigned_to
    if a.affected_user:
        body["affected_user"] = a.affected_user
    if a.cmdb_ci:
        body["cmdb_ci"] = a.cmdb_ci

    body["work_notes"] = (f"[{_stamp()}] SIR created via automation by "
                          f"{os.environ.get('USER', 'unknown')}.")

    res = _call("POST", f"/api/now/table/{TABLE}", body=body)
    rec = res.get("result", {})
    print(f"Created {rec.get('number')}  sys_id={rec.get('sys_id')}")
    print(f"https://{INSTANCE}/nav_to.do?uri={TABLE}.do?sys_id={rec.get('sys_id')}")
    return rec


def note(a):
    sys_id, _ = find(a.number)
    text = a.text
    if a.file:
        text = open(a.file).read()
    stamped = f"[{_stamp()}] {os.environ.get('USER', 'analyst')}: {text}"
    field = "comments" if a.customer_visible else "work_notes"
    _call("PATCH", f"/api/now/table/{TABLE}/{sys_id}", body={field: stamped})
    print(f"Added {field} to {a.number}")


def set_state(a):
    sys_id, rec = find(a.number)
    if a.to not in STATES:
        sys.exit(f"Unknown state '{a.to}'. Known: {', '.join(STATES)}")
    body = {
        "state": str(STATES[a.to]),
        "work_notes": f"[{_stamp()}] State changed to {a.to} by "
                      f"{os.environ.get('USER', 'analyst')}."
                      + (f" {a.reason}" if a.reason else ""),
    }
    _call("PATCH", f"/api/now/table/{TABLE}/{sys_id}", body=body)
    print(f"{a.number}: state {rec.get('state')} -> {a.to} ({STATES[a.to]})")


def attach(a):
    sys_id, _ = find(a.number)
    if not os.path.isfile(a.file):
        sys.exit(f"No such file: {a.file}")
    fname = os.path.basename(a.file)
    ctype = mimetypes.guess_type(fname)[0] or "application/octet-stream"
    auth, extra = _auth()
    with open(a.file, "rb") as fh:
        r = requests.post(
            f"https://{INSTANCE}/api/now/attachment/file",
            auth=auth,
            headers={"Content-Type": ctype, "Accept": "application/json", **extra},
            params={"table_name": TABLE, "table_sys_id": sys_id, "file_name": fname},
            data=fh.read(), timeout=180,
        )
    if r.status_code >= 400:
        sys.exit(f"Attachment failed [{r.status_code}]: {r.text[:400]}")
    size = os.path.getsize(a.file)
    print(f"Attached {fname} ({size:,} bytes) to {a.number}")
    note(argparse.Namespace(number=a.number, text=f"Evidence attached: {fname} "
                            f"({size:,} bytes)", file=None, customer_visible=False))


def get(a):
    _, rec = find(a.number)
    interesting = ["number", "short_description", "state", "category", "subcategory",
                   "priority", "impact", "urgency", "assigned_to", "assignment_group",
                   "opened_at", "sys_updated_on", "close_code", "close_notes",
                   "affected_user", "cmdb_ci", "substate"]
    out = {}
    for k in interesting:
        v = rec.get(k)
        if isinstance(v, dict):
            v = v.get("display_value") or v.get("value")
        if v not in (None, ""):
            out[k] = v
    print(json.dumps(out, indent=2))


def close(a):
    sys_id, _ = find(a.number)
    body = {
        "state": str(STATES["Closed"]),
        "close_code": a.code,
        "close_notes": a.notes,
        "work_notes": f"[{_stamp()}] Closed by {os.environ.get('USER', 'analyst')}. "
                      f"Resolution: {a.code}",
    }
    _call("PATCH", f"/api/now/table/{TABLE}/{sys_id}", body=body)
    print(f"Closed {a.number} as '{a.code}'")


def states(a):
    """Dump the actual state choice list from the instance so you can correct STATES."""
    res = _call("GET", "/api/now/table/sys_choice",
                params={"sysparm_query": f"name={TABLE}^element=state",
                        "sysparm_fields": "label,value,inactive",
                        "sysparm_limit": 100})
    rows = res.get("result", [])
    if not rows:
        print(f"No state choices found for table '{TABLE}'. "
              f"Check the table name and the account's read access to sys_choice.")
        return
    print(f"State choices for {TABLE}:")
    for r in sorted(rows, key=lambda x: int(x.get("value") or 0)):
        flag = "  (inactive)" if r.get("inactive") in ("true", True) else ""
        print(f"  {r.get('value'):>5}  {r.get('label')}{flag}")
    print("\nUpdate the STATES dict in this script to match.")


def main():
    p = argparse.ArgumentParser(description="ServiceNow SIR helper for SOC runbooks")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("create")
    s.add_argument("--title", required=True)
    s.add_argument("--description", default="")
    s.add_argument("--category", required=True,
                   help="e.g. Phishing, Malware, Ransomware, Account Compromise, "
                        "Data Loss, Lateral Movement, Denial of Service")
    s.add_argument("--subcategory", default="")
    s.add_argument("--impact", type=int, default=3, choices=[1, 2, 3])
    s.add_argument("--urgency", type=int, default=3, choices=[1, 2, 3])
    s.add_argument("--state", default="Analysis", choices=list(STATES))
    s.add_argument("--assignment-group", dest="assignment_group", default="")
    s.add_argument("--assigned-to", dest="assigned_to", default="")
    s.add_argument("--affected-user", dest="affected_user", default="")
    s.add_argument("--cmdb-ci", dest="cmdb_ci", default="")
    s.set_defaults(func=create)

    s = sub.add_parser("note")
    s.add_argument("--number", required=True)
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--text")
    g.add_argument("--file", help="read the note body from a file")
    s.add_argument("--customer-visible", action="store_true",
                   help="write to comments instead of work_notes")
    s.set_defaults(func=note)

    s = sub.add_parser("state")
    s.add_argument("--number", required=True)
    s.add_argument("--to", required=True, choices=list(STATES))
    s.add_argument("--reason", default="")
    s.set_defaults(func=set_state)

    s = sub.add_parser("attach")
    s.add_argument("--number", required=True)
    s.add_argument("--file", required=True)
    s.set_defaults(func=attach)

    s = sub.add_parser("get")
    s.add_argument("--number", required=True)
    s.set_defaults(func=get)

    s = sub.add_parser("close")
    s.add_argument("--number", required=True)
    s.add_argument("--code", required=True,
                   help="e.g. 'True Positive - Contained', 'False Positive', "
                        "'Benign True Positive'")
    s.add_argument("--notes", required=True,
                   help="Root cause, scope, actions taken, follow-ups")
    s.set_defaults(func=close)

    s = sub.add_parser("states")
    s.set_defaults(func=states)

    a = p.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
