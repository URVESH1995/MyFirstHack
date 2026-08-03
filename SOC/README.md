# SOC Incident Response Pack
**Splunk Cloud (+ Enterprise Security) · Microsoft Defender XDR · ServiceNow SecOps**
Version 1.0 · Owner: SOC · Review: quarterly, or after any P1

---

## What's in here

```
README.md                              this file — start here
soc-incident-response-playbooks.md     the index: all 17 playbooks, priority matrix,
                                       universal triage checklist, escalation matrix,
                                       evidence handling, metrics
savedsearches.conf                     18 ES correlation searches, all shipped disabled
runbooks/
  runbook-PB01-phishing.md             PB-01  Phishing / malicious email
  runbooks-endpoint.md                 PB-02  Malware
                                       PB-03  Ransomware
                                       PB-07  LOLBin / suspicious scripting
                                       PB-15  Unauthorized RMM
  runbooks-identity.md                 PB-04  Account compromise
                                       PB-05  Brute force / spray / MFA fatigue
                                       PB-09  Privilege escalation
  runbooks-network-lateral.md          PB-06  Command & control / beaconing
                                       PB-08  Lateral movement
                                       PB-13  Denial of service
  runbooks-data-insider.md             PB-10  Data exfiltration / insider threat
                                       PB-16  Lost or stolen device
  runbooks-appsec-cloud.md             PB-11  Web application attack
                                       PB-12  Vulnerability exploitation
                                       PB-14  Cloud / SaaS misconfiguration
                                       PB-17  Third-party / supply chain
scripts/
  defender_response.py                 MDE containment: isolate, bulk-isolate, collect
                                       package, AV scan, restrict execution, quarantine
                                       file, indicators, advanced hunting
  Invoke-IdentityContainment.ps1       Entra + Exchange: revoke sessions, block sign-in,
                                       clear forwarding, remove inbox rules, and full
                                       evidence collection for the SIR
  servicenow_sir.py                    Create SIRs, add timestamped work notes, change
                                       state, attach evidence, close with resolution
  splunk_deploy.py                     Backtest and deploy correlation searches and
                                       lookups to Splunk Cloud via REST
lookups/
  9 CSVs                               the noise-reduction layer — populate these first
```

Every runbook follows the same shape: **decision tree → queries → containment options with trade-offs → verification checklist → false positives → ServiceNow fields**.

The "options" framing is deliberate. Containment steps are presented as choices with stated trade-offs rather than single instructions, because the right answer differs between a user laptop and a production database primary. Where there genuinely is only one defensible answer, the runbook says so.

---

## If you are on ES 8.x / Mission Control — read this first

**[ES8-MISSION-CONTROL-ADDENDUM.md](ES8-MISSION-CONTROL-ADDENDUM.md)**

This pack was written against ES 7.x conventions (correlation searches, notables, Incident
Review). If you triage in Mission Control you are on ES 8.x, where those are called
detections, findings and the analyst queue. The conf still deploys and the attributes are
still valid, but five detections define two risk entities each and will produce two findings
per trigger unless you set output types — which changes the backtest maths in step 3 below.
The addendum covers the terminology map, the specific per-detection fixes, and how to turn
these runbooks into Mission Control response plans ().

---

## Deployment order

Do it in this order. Skipping to step 4 is the most common way these packs fail.

**1. Verify your data (30 minutes)**
```
| tstats count where index=* by index, sourcetype | sort - count
```
Every SPL query in this pack assumes index and sourcetype names that are almost certainly not yours. Map them, then find-and-replace. The KQL is safe as-is because Advanced Hunting table schemas are fixed.

Also confirm which CIM data models are accelerated:
```
| tstats count from datamodel=Endpoint.Processes by index
| tstats count from datamodel=Authentication by index
| tstats count from datamodel=Network_Traffic by index
| tstats count from datamodel=Web by index
```
If any of these return nothing, the `tstats` searches that use them will silently return zero — which looks like "no threats" and is much worse than a noisy rule.

**2. Populate the lookups (a few days of real work)**
| Lookup | Priority | Without it |
|---|---|---|
| `corporate_ip_ranges.csv` | **Critical** | Every identity search misclassifies internal as external |
| `beacon_allowlist.csv` | **Critical** | Beaconing and DNS tunnelling rules are unusable, not just noisy |
| `expected_admin_hosts.csv` | **Critical** | Lateral movement rule fires on every vuln scan |
| `privileged_groups.csv` | High | Privilege escalation rule misses your custom groups |
| `phishing_simulation_senders.csv` | High | Every awareness campaign generates real incidents |
| `rmm_tools.csv` | Medium | Pre-populated with 36 tools; set `approved=true` for yours |
| `personal_cloud_storage.csv` | Medium | Pre-populated with 41 domains; adjust `sanctioned` |
| `corporate_asn.csv` | Medium | Can't make ASN-level blocking decisions in PB-05 |
| `redteam_infrastructure.csv` | As needed | Deconfliction during engagements |

```bash
export SPLUNK_HOST=yourstack.splunkcloud.com SPLUNK_TOKEN=...
for f in lookups/*.csv; do ./scripts/splunk_deploy.py upload-lookup --file "$f"; done
```

**3. Backtest every search before enabling anything**
```bash
./scripts/splunk_deploy.py backtest --conf savedsearches.conf --earliest -7d
```
Read the verdict column: `OK - enable` (≤20/day), `TUNE FIRST` (21–100/day), `DO NOT ENABLE` (>100/day), `ZERO - verify data` (check your index mapping, don't assume you're clean).

**4. Deploy disabled, then enable one at a time**
```bash
./scripts/splunk_deploy.py deploy --conf savedsearches.conf
./scripts/splunk_deploy.py enable --name "Endpoint - Volume Shadow Copy Deletion - Rule"
```
Watch each for five business days before enabling the next. Suggested order — highest fidelity first, so analysts learn to trust the queue:
1. `Endpoint - Volume Shadow Copy Deletion` (near-zero FP, catastrophic if missed)
2. `Endpoint - Web Server Process Spawning Command Shell`
3. `Endpoint - Office Application Spawning Script Interpreter`
4. `Access - Successful Authentication After Brute Force`
5. `Access - MFA Push Bombing Followed By Approval`
6. `Phishing - Credential Submission Following Malicious URL Click`
7. `Identity - Privileged Group Or Role Membership Change`
8. …then the rest, leaving the beaconing, DNS tunnelling and lateral movement rules for last since they depend most on lookup quality.

**5. Set up the scripts**
```bash
# MDE app registration — see the header of defender_response.py for exact permissions
export MDE_TENANT_ID=... MDE_CLIENT_ID=... MDE_CLIENT_SECRET=...
export SN_INSTANCE=yourinstance.service-now.com SN_USER=... SN_PASSWORD=...
```
Pull secrets from your vault at runtime. Don't put them in a shell profile.

**Verify your SIR state values before relying on the ServiceNow script:**
```bash
./scripts/servicenow_sir.py states
```
The numeric state values in the script are ServiceNow out-of-box defaults and are very commonly customized. Correct the `STATES` dict to match your instance.

**6. Fill in the blanks that only you can fill in**
| Where | What |
|---|---|
| `soc-incident-response-playbooks.md` §7 | Escalation matrix — real names and phone numbers |
| `runbooks-data-insider.md` PB-10 authorization gate | Who authorizes investigation of a named employee at your organization |
| PB-13 | ISP / scrubbing provider contact and account number |
| PB-03 | Backup owner, IR retainer contact, crisis bridge details |
| PB-17 | Complete vendor access enumeration (all 14 categories) |
| All | Your Splunk index names |

---

## Cross-references between runbooks

Incidents rarely stay in one playbook. The common paths:

```
PB-01 Phishing ──┬── credentials entered ──→ PB-04 Account compromise
                 └── attachment ran ────────→ PB-02 Malware
                                                 │
PB-02 Malware ───┬── C2 observed ─────────────→ PB-06 Command & control
                 ├── infostealer ────────────→ PB-04 (rotate everything cached)
                 ├── credential dumper ──────→ PB-08 Lateral movement
                 └── ransomware family ──────→ PB-03 Ransomware
                                                 │
PB-04 Account ───┬── privileged role granted ─→ PB-09 Privilege escalation
                 ├── files downloaded ───────→ PB-10 Data exfiltration
                 └── account sending mail ───→ PB-01 §7 internal spread
                                                 │
PB-05 Spray ─────── any success ──────────────→ PB-04
PB-08 Lateral ───┬── heading for backups ────→ PB-03 (protect backups NOW)
                 └── heading for shares ─────→ PB-10
PB-11 Web attack ─┬── shell spawned ──────────→ PB-02, then PB-08 for the pivot
                  └── SSRF to metadata ───────→ PB-14 Cloud
PB-12 Vuln ──────── exploitation found ───────→ PB-11 / PB-02 / PB-08
PB-15 RMM ───────── pushed remotely ──────────→ PB-08
PB-17 Third party ─ vendor creds abused ──────→ PB-04, PB-08
PB-13 DDoS ──────── ALWAYS run the smokescreen check → any of the above
```

---

## What this pack does not do

Stated plainly so nobody discovers it at 3am.

- **The SPL will not work unmodified.** Index and sourcetype names are placeholders. Budget half a day for mapping.
- **`tstats` searches depend on accelerated CIM data models.** If yours aren't accelerated, they return zero silently. Verify in step 1.
- **Microsoft renames Defender portal menus regularly.** Click paths are accurate as written but may drift. The portal search bar resolves page names reliably after renames.
- **ServiceNow SIR state values are instance-specific.** Run `servicenow_sir.py states` and correct them.
- **The PowerShell script deliberately does not reset passwords.** Resets need a human delivering the credential out-of-band. Automating it puts a plaintext credential in a log or console buffer.
- **The scripts do not revoke OAuth consents automatically.** Granted scopes need human review first — deleting the wrong enterprise application breaks production. The script reports them and flags high-risk scopes.
- **No script here deletes data, moves money, or resets KRBTGT.** KRBTGT is a manual, planned, two-stage operation; scripting it is how you cause an authentication outage on top of an incident.
- **Detection coverage is not comprehensive.** 18 searches across 17 playbook types is a starting set, not full ATT&CK coverage. Map what you have with ATT&CK Navigator or DeTT&CT and work the gaps — Initial Access, Credential Access and Exfiltration usually hurt most.
- **Legal and regulatory guidance is generic.** Notification obligations differ substantially by jurisdiction, and monitoring/investigation rules for employees differ even more (India, EU/GDPR, US state law, works-council agreements). Nothing here is legal advice — your Legal team owns those determinations, and PB-10's authorization gate exists for exactly this reason.
- **This pack assumes you have the telemetry.** Several runbooks call out gaps to raise as findings when you discover you don't: PowerShell script block logging (EventCode 4104), proxy and DNS logs in Splunk, storage diagnostic logging, LAPS. Those gaps are worth more attention than any rule tuning.

---

## Maintenance

Every closed incident answers three questions in the Post Incident Review:
1. Could we have detected this earlier? → new correlation search or Defender custom detection
2. Could we have prevented it? → Change or Problem record
3. Was the runbook right? → update the file, note the change date

Track per-rule false-positive rate monthly. It's the most actionable number you have, and a rule above ~20 findings/day is actively training your analysts to ignore the queue.

Review the lookups quarterly. A forgotten exclusion in `expected_admin_hosts.csv` or `beacon_allowlist.csv` is a blind spot an attacker can walk straight through — stale exclusions are a bigger long-term risk than the noise they were added to suppress.
