# ADDENDUM — Splunk ES 8.x / Mission Control

The pack was written against ES 7.x conventions: correlation searches, notables, Incident Review. If you're triaging in **Mission Control**, you're on ES 8.x, and several things change. Nothing in the pack is wasted, but read this before deploying `savedsearches.conf`.

**Version matters a lot here.** Behaviour differs meaningfully between 8.0 and 8.1+, and Splunk docs currently run to 8.6. Confirm your exact version before acting on §3:

```
| rest /services/apps/local/SplunkEnterpriseSecuritySuite | table label, version
```

---

## 1. Terminology map

| Pack says (ES 7.x) | ES 8.x calls it | Notes |
|---|---|---|
| Correlation search | **Detection** — specifically an *event-based detection* (EBD) | Also *finding-based detections*, which run over findings rather than raw events |
| Notable event | **Finding** | Findings combine what used to be notables and risk events into one object |
| Risk event / risk modifier output | **Intermediate finding** | Does **not** appear in the analyst queue by design |
| Incident Review | **Mission Control** → analyst queue | |
| Episode / grouped notables | **Finding group**, then **Investigation** | An investigation is built from one or more findings |
| Adaptive response action | Still adaptive response, surfaced as **Respond** options on a task | |
| — (new) | **Response plan** | Templated phases + tasks + embedded searches + playbook hooks |
| — (new) | **Investigation type** | You can bind a response plan to an investigation type so it auto-applies |

The underlying plumbing is still called "notable" — the alert action is `notable`, the index is `notable`, and the log is `notable_modalert.log`. That's why the conf attributes in the pack still work.

Where the runbooks say "Incident Review → open notable → Actions → drilldown", read: **Mission Control → select the finding → side panel → Start investigation**.

---

## 2. What still works unchanged

Confirmed against ES 8.5/8.6 documentation:

- **`savedsearches.conf` is still a supported deployment path.** Splunk's own detection-versioning documentation lists three ways to modify a detection: the `saved/searches` API, packaging detections in an app, or editing `savedsearches.conf` directly on-premises. `scripts/splunk_deploy.py` needs no changes.
- **The conf attributes in the pack are still valid.** `action.correlationsearch.enabled`, `action.correlationsearch.label`, `action.correlationsearch.annotations`, `action.notable.param.*` and `action.risk.param.*` all still exist in 8.5+. Splunk's own docs use `action.correlationsearch.enabled` and `action.notable.param.security_domain` in their example REST queries for listing detections.
- **Legacy detections are not rewritten on upgrade or import.** Detections created in 7.x style stay as-is in 8.x until an analyst edits them in the UI.
- All KQL is unaffected — that's Defender, not Splunk.
- The lookups, runbook logic, decision trees, queries, and the Defender/ServiceNow scripts are unaffected.

---

## 3. What changes — the findings multiplication problem

This is the one that will bite you.

In ES 8.x, a detection's risk entities each have an **output type**: Finding or Intermediate Finding. In **ES 8.0**, a detection configured to create findings produces **a separate finding per risk entity**. Splunk Lantern's upgrade guidance states this plainly and notes there is no workaround in 8.0. **ES 8.1 and later** let you toggle the output type per entity, so only the entities you choose land in the analyst queue.

Five detections in the pack define two risk entities each. On ES 8.0 they will produce **two findings per trigger**. Recommended output types once you're on 8.1+:

| Detection | Entities | Finding | Intermediate | Why |
|---|---|---|---|---|
| `Access - Successful Authentication After Brute Force` | `user`, `src_ip` | **user** | src_ip | The compromised account is the thing you contain. The source IP is context, and it'll be shared across many victims. |
| `Endpoint - Volume Shadow Copy Deletion` | `dest`, `user` | **dest** | user | Isolate the host. The user is often SYSTEM or a service account. |
| `Endpoint - Suspicious Encoded PowerShell Execution` | `dest`, `user` | **dest** | user | Same reasoning. |
| `Endpoint - Office Application Spawning Script Interpreter` | `dest`, `user` | **dest** | user | Same. The user matters for the PB-01 pivot but doesn't need its own queue item. |
| `Identity - Privileged Group Or Role Membership Change` | `target`, `actor` | **actor** | target | Counter-intuitive but correct: the authority question in PB-09 is about the *actor*. One actor granting five people admin should be one finding, not five. |

Every other detection in the pack has a single risk entity and behaves the same in 7.x and 8.x.

**Recalibrate the backtest thresholds in the README.** The "≤20 findings/day is fine" guidance in step 3 counts *findings*, not detection triggers. On ES 8.0 the five detections above double, so a detection producing 15 triggers/day produces 30 findings/day and lands in "TUNE FIRST" territory. `splunk_deploy.py backtest` counts SPL result rows, so it reports triggers — mentally double the number for those five until you've set output types.

### 3.1 Two more ES 8 requirements

**The detection editor requires the risk/scoring section on every detection**, whether or not you use RBA. One detection in the pack has no `action.risk` block:

- `Phishing - Mass Campaign Delivered To Inbox - Rule`

It will import and run fine as a legacy stanza, but the moment you open it in the detection editor you'll be required to add a risk entity. Add this to the stanza now so the UI doesn't force an arbitrary choice on you later:

```
action.risk = 1
action.risk.param._risk = [{"risk_object_field":"SenderMailFromDomain","risk_object_type":"other","risk_score":30}]
action.risk.param._risk_message = Phishing campaign from $SenderMailFromDomain$ delivered to $recipient_count$ inboxes
```

**The entity field must exist in the SPL output**, or findings fail silently — the scheduler logs `fired=1`, the modaction log shows success, and the notable index stays empty. Splunk has a support article on exactly this failure mode. Audited across all 18 detections in the pack: **every risk entity field is present in its SPL output.** No fixes needed. If you edit any SPL, re-check — this is the most common cause of "my detection runs but nothing appears in the queue."

One stylistic note: `Identity - Privileged Group Or Role Membership Change` uses `target` and `actor` as entity field names. That works, since what matters is the field's *value*, not its name. But renaming them to `user` and `src_user` in the SPL would align with CIM convention and make the detection easier for the next person to read. Optional.

### 3.2 The upgrade trap

Legacy stanzas convert to event-based detections **the first time an analyst opens and saves them in the detection editor**. Before that, they behave as 7.x-style. After that, ES rewrites the stanza and the output behaviour may change — on 8.1+, migrated detections reportedly default all previously-defined risk entities to "Finding", which is how a quiet detection becomes a noisy one overnight.

Practical consequence: **decide the output types deliberately and set them in the conf up front**, rather than letting the first analyst who clicks into a detection make the decision by accident. Track which detections have been touched:

```
| rest splunk_server=local count=0 /servicesNS/-/SplunkEnterpriseSecuritySuite/saved/searches
| where match('action.correlationsearch.enabled', "1|[Tt]|[Tt][Rr][Uu][Ee]")
| table title, disabled, actions, action.risk.param._risk, updated
| sort - updated
```

---

## 4. Verification searches after deploying

```
| rest splunk_server=local count=0 /servicesNS/-/SplunkEnterpriseSecuritySuite/saved/searches
| where match('action.correlationsearch.enabled', "1|[Tt]|[Tt][Rr][Uu][Ee]")
| rename eai:acl.app as app, title as detection,
         action.correlationsearch.label as label,
         action.notable.param.security_domain as security_domain
| table detection, app, security_domain, disabled, cron_schedule
| sort detection
```
```
# Did a specific detection actually fire?
index=_internal sourcetype=scheduler savedsearch_name="Endpoint - Volume Shadow Copy Deletion - Rule" NOT fired=0
| table _time, savedsearch_name, result_count, alert_actions, fired, suppressed, skipped
```
```
# Findings actually landing in the queue, by detection
index=notable earliest=-7d
| stats count dc(orig_sid) as triggers min(_time) as firstTime max(_time) as lastTime by search_name
| eval findings_per_trigger=round(count/triggers,2)
| convert ctime(firstTime) ctime(lastTime)
| sort - count
```
That last one is the important one. `findings_per_trigger` greater than 1 confirms the multiplication described in §3, and tells you exactly which detections to fix first.
```
# Intermediate findings (the old risk index)
index=risk earliest=-7d
| stats count sum(risk_score) as total_score by risk_object, risk_object_type
| sort - total_score
```

---

## 5. The bigger opportunity: turn the runbooks into Response Plans

This is the part worth real effort. Right now the pack is markdown files an analyst has to read in another window. Mission Control's response plans put the same content **inside the investigation**, with the queries as one-click embedded searches and containment steps as tasks that can trigger a playbook.

The mapping is close to one-to-one:

| Runbook element | Response plan element |
|---|---|
| Runbook (PB-01, PB-02, …) | Response plan |
| Major section (Triage / Scope / Contain / Eradicate / Verify) | Phase |
| Numbered step | Task, with an owner |
| Query (Q4.1, Q8.2, …) | Search embedded in the task — analyst clicks the magnifier to run it |
| Containment option | Task with an adaptive response action or SOAR playbook attached |
| Verification checklist | Final phase, one task per checklist item |
| Decision tree | Task description, plus branch-specific tasks the analyst skips or completes |
| Runbook selection ("which playbook is this?") | **Investigation type** — bind the plan to the type so it auto-applies |

Response plans support `$token$` substitution for investigation fields such as `status`, `urgency`, `sensitivity` and `investigation_id`, so an embedded search can be scoped to the current investigation rather than hardcoded.

Built-in plans include a NIST 800-61 template. It can't be edited directly, but you can copy it and adapt — which is a sensible starting point, since the pack's master index is already organised around the NIST 800-61 lifecycle.

`response-plans/response-plans.yaml` in this pack contains the phases, tasks and embedded searches for the runbooks, structured to match the UI fields so entering them is mechanical rather than a design exercise.

**One honest limitation:** I could not find a documented, supported REST API for creating response plans programmatically. They're built in **Security content → Response plans**, and bound to types in **Configure → Findings and investigations**. They live in KV store, so a loader is technically possible, but writing to undocumented ES collections is the kind of thing that breaks on the next upgrade — I'd rather tell you that than hand you a script that quietly corrupts your instance. Budget UI data-entry time, and start with the three or four playbooks you actually run weekly.

---

## 6. A question the pack can't answer for you

You now have two case-management systems: **Mission Control investigations** and **ServiceNow SIR**. The pack assumes ServiceNow is the system of record — every runbook ends with ServiceNow fields, and `scripts/servicenow_sir.py` exists to feed it.

That's still a legitimate choice, but you need to pick one deliberately:

| Model | Works when | Cost |
|---|---|---|
| **ServiceNow is the record; Mission Control is the workspace** | ServiceNow is your enterprise-wide ITSM/SecOps platform, non-SOC teams need visibility, and reporting is already built there | Analysts work in two tools; you need bidirectional sync or you get drift. Keep `servicenow_sir.py`. |
| **Mission Control is the record; ServiceNow gets a summary** | The SOC is largely self-contained and you want response plans driving the workflow | Non-SOC stakeholders lose visibility unless you push summaries. Reduce `servicenow_sir.py` to create-and-close-only. |
| **Both, fully synced** | You have the Splunk–ServiceNow integration configured and maintained | Real ongoing maintenance; sync failures produce contradictory tickets |

The failure mode to avoid is the ambient one: half the analysts update the investigation, half update the SIR, and neither record is complete when someone asks what happened. Decide, write it down, and make the runbooks say which tool owns which field.

---

## 7. Revised deployment order

Replaces steps 3–4 in the main README.

1. Confirm your ES version (§0 query above).
2. Verify data and populate lookups — unchanged, still steps 1–2.
3. Add the missing `action.risk` block to `Phishing - Mass Campaign Delivered To Inbox` (§3.1).
4. Decide output types for the five multi-entity detections (§3) and set them in the conf **before** deploying.
5. Backtest. Double the reported count for those five detections if you're on 8.0.
6. Deploy disabled, enable one at a time — unchanged.
7. After a week, run the `findings_per_trigger` search in §4 and fix anything above 1 that you didn't intend.
8. Build response plans for your top 3–4 playbooks, bind them to investigation types, and only then work through the rest.
9. Decide the Mission Control vs ServiceNow question in §6 and record it.

---

## Sources

- Splunk Docs, *Monitor your security operations center with findings* (ES 8) — findings replace notables, intermediate findings replace risk events, intermediate findings are not shown in the analyst queue
- Splunk Docs, *Use detections to search for threats* (ES 8.1–8.5) — per-entity output types, ES 8.0 behaviour, backward compatibility of legacy stanzas
- Splunk Docs, *Use detection versioning* (ES 8.5) — savedsearches API / app packaging / conf editing as the three modification paths
- Splunk Docs, *Overview of Mission Control* and *Respond to investigations with response plans* (ES 8.3–8.6) — analyst queue, investigations, response plan phases/tasks/tokens
- Splunk Lantern, *Upgrading to Enterprise Security 8.0.x — Configuration and customization* — correlation searches become EBDs; mandatory risk section; multiple risk objects produce multiple results, no workaround in 8.0
- Splunk support article, *Findings (notables) fail to be created after upgrading to ES 8.0* — entity field must match a field in the detection SPL
- TekStream, *Splunk ES 8.1 output type improvements* (vendor blog, not Splunk documentation) — reported default output types for new vs migrated detections in 8.1

Verify anything version-specific against your own instance before relying on it. Splunk has shipped 8.0 through 8.6 quickly and behaviour has shifted between point releases.
