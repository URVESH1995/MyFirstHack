# DATA & INSIDER RUNBOOKS
### PB-10 Data Exfiltration / Insider Threat · PB-16 Lost or Stolen Device

---
---

# PB-10 · Data Exfiltration / Insider Threat

**Default priority:** P1 if sensitive data confirmed to have left · P2 for anomalous volume pending assessment

> ## Authorization gate — read before running a single query
>
> This is the only runbook with a hard stop before investigation.
>
> **If the subject is a named employee and this is not an external-attacker exfiltration, you must have authorization before you begin.** Who authorizes varies by organization — typically HR plus Legal, sometimes an Employee Relations lead or a works council in some jurisdictions. Find out who signs off *at your organization* and record it in this runbook today, not during the incident.
>
> Investigating an employee without authorization can invalidate evidence, breach employment law and works-council agreements, breach privacy law (monitoring rules differ substantially by jurisdiction — India, EU/GDPR, and US state law all differ), and expose you and your employer personally.
>
> **What you may always do without special authorization:** respond to a technical alert, contain a data flow, and preserve evidence. **What needs authorization:** targeted investigation of an individual's activity, reading their email content, reviewing their browsing history, or building a behavioural profile.
>
> If the exfiltration is by an external attacker using a compromised account, this gate does not apply — that's PB-04 plus this runbook's technical steps.
>
> **Authorized by (fill in):** _______________  **Escalation contact:** _______________

---

## Step 1 — Preserve before you contain

Reversed from most runbooks. If this becomes an HR matter, a dismissal, litigation, or a criminal referral, evidence integrity is the whole case.

| # | Action | How |
|---|---|---|
| 1 | **Legal hold on the mailbox** | Purview → eDiscovery, or `Set-Mailbox -LitigationHoldEnabled $true`. Do this before anything the user might notice. |
| 2 | **Preserve OneDrive / SharePoint** | Retention hold via Purview |
| 3 | **Collect the endpoint investigation package** | Defender → device → Collect investigation package |
| 4 | **Snapshot the device if virtual** | Infrastructure |
| 5 | **Do NOT let the user wipe or return-and-reimage the device** | Coordinate with IT asset management immediately — the standard offboarding wipe destroys your evidence |
| 6 | **Hash and log every artifact** | `sha256sum`; record in the SIR with collector name and UTC time |
| 7 | **Chain of custody entry** | Who, when, from where, hash, storage location. Every handoff logged. |
| 8 | **Do not tip off the subject** | No "just checking something" messages. Coordinate timing with HR. |

**Do not** interview the subject, mention the investigation to their manager without authorization, or take visible action (account disable) before HR has agreed on timing — unless data is actively leaving right now, in which case containment wins and you document why.

---

## Step 2 — Decision tree

```
Anomalous data movement detected
│
├─ Is the actor an external attacker on a compromised account?
│   ├─ YES → PB-04 for the identity, then continue here for the data assessment.
│   │        No HR authorization gate.
│   └─ NO (apparent insider) → AUTHORIZATION GATE. Stop until cleared.
│
├─ Is data actively moving right now?
│   ├─ YES → contain the channel now (block destination, kill session, disable account).
│   │        Document that containment preceded full authorization because of
│   │        active loss. That is defensible; a week of unauthorized investigation is not.
│   └─ NO  → preserve first (Step 1), then proceed under authorization.
│
├─ WHAT data? (Q10.5) — determines everything downstream
│   ├─ Public / non-sensitive               → P4. Policy conversation, not an incident.
│   ├─ Internal-confidential (plans, code,
│   │  pricing, customer lists)             → P2. Business/IP harm. Legal + business owner.
│   ├─ Personal data / PII / health / payment → P1. NOTIFIABLE BREACH ASSESSMENT.
│   │                                            Legal owns the clock. Get them the facts
│   │                                            fast: what, how much, whose, when, where to.
│   ├─ Regulated (financial records, health,
│   │  government/defence)                  → P1. Sector regulator involvement.
│   └─ Unknown                              → P2 minimum until classified. Do not assume
│                                              low sensitivity because the volume was small.
│
├─ WHERE did it go? (Q10.1–Q10.4)
│   ├─ Personal cloud storage               → recoverable-ish; request deletion, get written
│   │                                            confirmation, but assume copies persist
│   ├─ Personal email                       → same
│   ├─ USB / removable media                → physical recovery; device may be retrievable
│   ├─ Printed                              → physical; check print logs and badge access
│   ├─ Competitor / known third party       → Legal, potentially urgent injunction territory
│   ├─ Attacker infrastructure              → assume permanent loss and publication
│   └─ Personal device via sanctioned sync   → may be recoverable via MDM wipe
│
├─ INTENT signals (weigh, don't conclude — you are not the adjudicator)
│   ├─ Resignation submitted or recruiter activity in the window
│   ├─ Access to data outside their normal role or team
│   ├─ Activity concentrated outside working hours
│   ├─ Archive creation immediately before upload (staging)
│   ├─ Attempts to evade monitoring (renaming files, encryption, splitting archives,
│   │  clearing history, using an unmanaged device)
│   ├─ Volume far outside their own historical baseline (Q10.6)
│   └─ Sudden broad access after a period of normal use
│   → Multiple signals present = present the pattern to HR/Legal as findings.
│     Your job is to report facts and patterns accurately, not to determine
│     intent or recommend disciplinary outcomes.
│
└─ Scope: is this one person or a group?
    └─ Multiple actors → potentially coordinated, or a cultural/process problem
       (e.g. everyone uses personal Dropbox because the sanctioned tool is unusable).
       The second is far more common and the fix is a product decision, not discipline.
```

---

## Step 3 — Queries

**Q10.1 — Outbound volume to personal cloud storage**
```
| tstats summariesonly=true allow_old_summaries=true
    sum(Web.bytes_out) as bytes_out count
    from datamodel=Web where Web.action!="blocked"
    by Web.user Web.src Web.site
| rename "Web.*" as "*"
| lookup personal_cloud_storage.csv domain as site OUTPUT service, sanctioned
| where isnotnull(service) AND sanctioned!="true"
| stats sum(bytes_out) as bytes_out sum(count) as requests
        values(site) as sites values(service) as services by user, src
| eval GB_out=round(bytes_out/1024/1024/1024,2)
| where GB_out >= 1
| sort - GB_out
```

**Q10.2 — All large outbound flows (catches destinations not on your list)**
```
index=proxy earliest=-30d
| stats sum(bytes_out) as bytes_out sum(bytes_in) as bytes_in count
        min(_time) as firstTime max(_time) as lastTime
        by user, dest_host
| eval GB_out=round(bytes_out/1024/1024/1024,2),
       out_in_ratio=round(bytes_out/(bytes_in+1),2)
| where GB_out > 0.5 AND out_in_ratio > 5
| convert ctime(firstTime) ctime(lastTime)
| sort - GB_out
```
`out_in_ratio > 5` distinguishes uploading from browsing. Browsing is inbound-heavy; exfiltration is outbound-heavy. This is the single most useful filter in this runbook.

**Q10.3 — SharePoint / OneDrive mass access and external sharing**
```
index=o365 sourcetype="o365:management:activity" earliest=-30d
  Operation IN ("FileDownloaded","FileSyncDownloadedFull","FileAccessed","FilePreviewed",
                "AnonymousLinkCreated","AnonymousLinkUsed","SharingInvitationCreated",
                "AddedToSecureLink","SecureLinkCreated","CompanyLinkCreated",
                "FileCopied","FileMoved")
| stats count dc(SourceFileName) as unique_files values(Operation) as ops
        values(SiteUrl) as sites min(_time) as firstTime max(_time) as lastTime
        by UserId, ClientIP
| where unique_files > 100
| convert ctime(firstTime) ctime(lastTime)
| sort - unique_files
```
```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileDownloaded","FileSyncDownloadedFull","AnonymousLinkCreated","SharingInvitationCreated")
| summarize Files=dcount(ObjectName), Ops=make_set(ActionType,5), IPs=make_set(IPAddress,10)
    by AccountDisplayName, bin(Timestamp,1d)
| where Files > 100
| order by Files desc
```

**Q10.4 — Removable media**
```kql
DeviceFileEvents
| where Timestamp > ago(30d) and ActionType == "FileCreated"
| where FolderPath matches regex @"^[D-Z]:\\" or FolderPath has "\\Removable"
| summarize Files=count(), TotalMB=round(sum(FileSize)/1048576.0,1),
            Extensions=make_set(tostring(split(FileName,".")[-1]), 15),
            FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by DeviceName, InitiatingProcessAccountName, FolderPath
| where TotalMB > 50
| order by TotalMB desc
```
```kql
// USB device insertions — correlate with the file writes above
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType in ("UsbDriveMounted","UsbDriveMount","UsbDriveUnmount","PnpDeviceConnected")
| project Timestamp, DeviceName, ActionType, AdditionalFields, InitiatingProcessAccountName
| order by Timestamp desc
```

**Q10.5 — What was actually taken (the question Legal will ask first)**
```kql
DeviceFileEvents
| where Timestamp between (datetime(2026-07-20) .. datetime(2026-07-25))
| where DeviceName =~ "HOST01"
| where ActionType in ("FileCreated","FileModified")
| where FolderPath has_any ("\\Removable","D:\\","E:\\") or InitiatingProcessFileName in~ ("rclone.exe","winscp.exe","7z.exe","winrar.exe")
| project Timestamp, FileName, FolderPath, FileSize, SHA256, InitiatingProcessFileName
| order by Timestamp asc
```
Then classify by filename and source location. Where possible get the actual file list from the source system (SharePoint audit gives filenames; proxy logs usually don't). If you cannot produce a file list, say so explicitly — Legal needs to know the difference between "we know exactly what left" and "we know 4 GB left and can infer the category."

**Q10.6 — Baseline comparison (is this actually anomalous for this person?)**
```
index=proxy earliest=-180d user="subject@corp.com"
| bin _time span=1d
| stats sum(bytes_out) as daily_bytes by _time
| eventstats avg(daily_bytes) as avg_daily stdev(daily_bytes) as sd_daily
| eval z_score=round((daily_bytes-avg_daily)/(sd_daily+1),2),
       GB=round(daily_bytes/1024/1024/1024,2)
| where z_score > 3
| sort - z_score
```
A z-score above 3 against the person's own 180-day baseline is a much stronger finding than a raw threshold, and it's fairer. Present this to HR rather than "they uploaded 2 GB" — 2 GB may be a normal Tuesday for a video editor.

**Q10.7 — Staging and exfiltration tooling**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("rclone.exe","megasync.exe","megacmd.exe","winscp.exe","filezilla.exe",
        "putty.exe","pscp.exe","psftp.exe","7z.exe","7za.exe","winrar.exe","rar.exe",
        "curl.exe","wget.exe","aws.exe","azcopy.exe","gsutil","gdrive.exe","dropbox.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName
| order by Timestamp asc
```
`rclone` with a configured remote is the single strongest technical indicator of deliberate bulk exfiltration in this list. Also look for archive creation with a password (`-p` / `-hp` flags) — that's evasion.

**Q10.8 — Email exfiltration**
```kql
EmailEvents
| where Timestamp > ago(30d) and EmailDirection == "Outbound"
| where SenderFromAddress =~ "subject@corp.com"
| join kind=leftouter (EmailAttachmentInfo | project NetworkMessageId, FileName, FileSize, FileType) on NetworkMessageId
| where isnotempty(FileName)
| summarize Messages=dcount(NetworkMessageId), Attachments=count(),
            TotalMB=round(sum(FileSize)/1048576.0,1), Files=make_set(FileName,50)
    by RecipientEmailAddress
| order by TotalMB desc
```
Personal email domains in the recipient list with meaningful attachment volume is a clean, easily-understood finding.

**Q10.9 — Print volume (frequently forgotten, sometimes the whole answer)**
```
index=print OR index=wineventlog sourcetype="WinEventLog:Microsoft-Windows-PrintService/Operational"
  EventCode=307 earliest=-30d
| stats count sum(Size) as total_bytes values(DocumentName) as documents by Param3, Param5
| sort - count
```

**Q10.10 — Access outside normal role (entitlement anomaly)**
```
index=o365 sourcetype="o365:management:activity" earliest=-90d
  Operation IN ("FileAccessed","FileDownloaded")
| stats dc(SiteUrl) as sites values(SiteUrl) as site_list count by UserId
| sort - sites
```
Compare the subject's site list to their team's typical list. Access to systems outside their function, especially newly acquired, is a strong signal — and it's also a legitimate access-review finding regardless of intent.

---

## Step 4 — Containment options

| Option | When | Trade-off |
|---|---|---|
| **Block the destination at proxy/DNS** | Always for unsanctioned destinations | Estate-wide benefit. Low risk. |
| **Revoke external sharing links** | Any external links created | Do it, and record which links and what they pointed to |
| **Disable the account** | Active exfiltration, or HR has agreed timing | Visible to the subject — coordinate with HR |
| **Contain the endpoint (isolate)** | Active exfiltration from a specific host | Visible |
| **Purview DLP policy in block mode** | Durable control for the data type involved | Project-scale; raise as a Change |
| **Retain the device** | Always if HR/Legal involvement is likely | Coordinate with asset management before the standard wipe |
| **Do nothing visible yet, monitor** | When HR needs time and loss is not ongoing | Legitimate here, unlike most runbooks — but time-boxed, documented, and authorized in writing |
| **MDM wipe of personal device** | Data on BYOD | Check your BYOD agreement permits it; selective wipe if available |

---

## Step 5 — Reporting to Legal

Give them these six things and nothing else editorialized:

1. **What data** — categories, and a file list if you have one. Say clearly if you don't.
2. **How much** — volume, record counts if determinable
3. **Whose data** — data subjects affected, and roughly how many
4. **When** — first and last activity, with timezone stated
5. **Where it went** — destination, and whether it is recoverable
6. **How you know** — the evidence, and its limitations

State confidence levels honestly. "Proxy logs show 4.2 GB uploaded to a personal Dropbox account; we cannot determine file names from proxy data alone" is far more useful than a confident guess. Legal makes the notification determination and owns the regulatory clock — you own the accuracy of the facts.

**Do not** write conclusions about the person's intent, motive, or character in the SIR. Write observed behaviour. The SIR may be disclosed in employment proceedings or litigation.

## Step 6 — Verification
- [ ] Authorization recorded, with names and date, before individual investigation began
- [ ] Legal hold and retention hold applied
- [ ] Endpoint evidence collected and hashed; chain of custody started
- [ ] Device retention arranged (not wiped)
- [ ] Data classified (Q10.5) — categories and volume determined, gaps stated explicitly
- [ ] Destination identified and blocked
- [ ] External sharing links revoked and recorded
- [ ] Baseline comparison run (Q10.6) — anomaly established against the person's own history
- [ ] All channels checked: cloud, email, USB, print, personal device sync, code repos
- [ ] Legal briefed with the six facts
- [ ] Access review raised for out-of-role access found (Q10.10)
- [ ] DLP / control gap raised as a Change

## Step 7 — False positives and the honest ones
| Pattern | Reality |
|---|---|
| Large legitimate transfer to a client or partner | Confirm with the business owner. Common and innocent. |
| Backup or sync software | Identify the process; add to allowlist |
| Developer pushing to a legitimate external repo | Check the repo is sanctioned; if not, that's a policy/product gap |
| Video, CAD, or media professional | Their baseline is enormous. Q10.6 handles this; raw thresholds do not. |
| Everyone in a team using personal Dropbox | **This is a product failure, not an insider threat.** The sanctioned tool is probably unusable. Report it that way — recommending discipline here would be both unfair and ineffective. |
| Departing employee taking their own personal files | Nuanced. Often genuinely innocent. Judge on data classification, not on the act of copying. |

## Step 8 — ServiceNow
Category `Data Loss` / `Insider Threat`. **Restrict the SIR** — these tickets should not be world-readable in your instance. Check that the read ACL is limited before you write anything sensitive.
Attach evidence by reference to a secured evidence store, not inline in the ticket.
Watchers: SOC Lead, Legal, HR (if authorized). Not the subject's manager unless HR agrees.

---
---

# PB-16 · Lost or Stolen Device

**Default priority:** P3 if encrypted, powered off, and no sensitive local data · **P2** standard · **P1** if unencrypted with sensitive data, or a privileged user's device

## Step 1 — Establish encryption status first
This single fact determines whether this is a paperwork exercise or a breach.

```kql
DeviceInfo
| where Timestamp > ago(7d) and DeviceName =~ "LAPTOP-042"
| summarize arg_max(Timestamp, *) by DeviceName
| project Timestamp, DeviceName, OSPlatform, OSVersion, IsAzureADJoined, JoinType,
          OnboardingStatus, DeviceType, LoggedOnUsers
```
```kql
DeviceTvmSecureConfigurationAssessment
| where DeviceName =~ "LAPTOP-042"
| where ConfigurationId has "bitlocker" or ConfigurationName has "BitLocker" or ConfigurationName has "encryption"
| project DeviceName, ConfigurationName, IsCompliant, IsApplicable, Timestamp
```
Also check Intune: `intune.microsoft.com` → **Devices** → device → **Hardware** / encryption report. And your BitLocker recovery key escrow — a key present in Entra/AD is good evidence encryption was actually enabled, not just policy-assigned.

**Record the evidence, not the assumption.** "Policy applied" is not "encryption confirmed enabled on that volume at that time." Legal will ask for the difference.

## Step 2 — Decision tree
```
Device reported lost or stolen
│
├─ Encryption confirmed enabled, device powered off when lost?
│   ├─ YES → data at rest is protected. P3. Wipe, revoke, document the
│   │        encryption evidence, close. Usually not a notifiable breach —
│   │        but that determination is Legal's, not yours.
│   └─ NO / UNKNOWN / device was powered on and unlocked
│       → P2 minimum. Treat local data as potentially accessible.
│
├─ Was it stolen (targeted) or lost (opportunistic)?
│   ├─ Lost in transit/public place, no other indicators → opportunistic. Most likely
│   │   outcome is a wiped-and-resold device. Standard response.
│   ├─ Stolen from a locked office, vehicle break-in targeting the bag,
│   │   taken during travel to a sensitive destination, or the user is a
│   │   high-value target → possible targeted collection. P1. Consider
│   │   the device compromised and any credentials on it burned.
│   └─ Multiple devices from the same team/site → coordinated. P1.
│
├─ What was on it?
│   ├─ Cached corporate credentials (always assume yes on Windows)
│   ├─ Locally stored sensitive files (check OneDrive Known Folder Move —
│   │   if enabled, most data is in the cloud, not local. Good news.)
│   ├─ Saved browser credentials / session cookies
│   ├─ VPN certificates / SSH keys / API tokens
│   ├─ Local database extracts or exports
│   └─ Nothing local (fully cloud, no local sync) → materially lower impact
│
├─ Any post-loss activity? (Q16.1)
│   ├─ YES, device checked in / authenticated after the reported loss time
│   │   → someone is using it. P1. This is now an active intrusion, not a
│   │     lost-property matter. Revoke everything, treat as compromised.
│   └─ NO → consistent with a powered-off or wiped device
│
├─ Privileged user?
│   └─ YES → P1. Rotate all their credentials and privileged access. Their
│            device is a route into tier-0.
│
└─ Personal (BYOD) device?
    └─ Check what your BYOD agreement permits. Selective wipe (corporate
       data only) is usually available and usually what's agreed. Full wipe
       of someone's personal device without the right agreement creates a
       legal problem of its own.
```

**Q16.1 — Post-loss activity check (run this every time)**
```kql
let lossTime = datetime(2026-07-30 18:00);
union
 (DeviceInfo | where DeviceName =~ "LAPTOP-042" and Timestamp > lossTime
    | project Timestamp, Source="DeviceInfo", Detail=strcat(PublicIP," ",LoggedOnUsers)),
 (DeviceLogonEvents | where DeviceName =~ "LAPTOP-042" and Timestamp > lossTime
    | project Timestamp, Source="Logon", Detail=strcat(AccountName," ",LogonType," ",RemoteIP)),
 (DeviceNetworkEvents | where DeviceName =~ "LAPTOP-042" and Timestamp > lossTime
    | project Timestamp, Source="Network", Detail=strcat(RemoteUrl," ",RemoteIP))
| order by Timestamp asc
```
```
index=azure_ad sourcetype="azure:aad:signin" earliest=-7d
  userPrincipalName="owner@corp.com"
| where _time > relative_time(now(),"-2d")
| table _time, ipAddress, "location.countryOrRegion", deviceDetail.displayName,
        deviceDetail.operatingSystem, appDisplayName, status.errorCode
| sort _time
```
Any authentication from the device after the loss time, from an IP the user doesn't recognise, means the device is in use. Escalate to P1 and run PB-04 on the owner.

## Step 3 — Response actions
| # | Action | Where | Notes |
|---|---|---|---|
| 1 | **Revoke sessions for the owner** | `entra.microsoft.com` → Users → Revoke sessions | Kills tokens cached on the device |
| 2 | **Reset the owner's password** | Same | Cached credentials on the device are now useless |
| 3 | **Remote wipe** | `intune.microsoft.com` → Devices → device → **Wipe** (corporate) or **Retire** (BYOD selective) | Wipe requires the device to come online. It may never. Issue it anyway. |
| 4 | **Mark the device non-compliant / block** | Intune compliance, and Entra → Devices → disable the device object | Prevents device-based CA from trusting it |
| 5 | **Isolate in Defender** | Defender → device → Isolate | Effective only if it checks in; costs nothing to queue |
| 6 | **Rotate certificates and keys** | PKI / cert authority | VPN certs, SSH keys, any API tokens known to be on the device |
| 7 | **Revoke BitLocker recovery key visibility** | Rotate the recovery key so a leaked key can't be reused | Often skipped; do it |
| 8 | **Asset record update** | ServiceNow CMDB → status Lost/Stolen | Also drives insurance and finance |
| 9 | **Police report** | Per policy / insurance requirement | Get the crime reference number into the SIR |
| 10 | **Notify the data owner** | Business owner of any sensitive local data | They may know things about the data you don't |

**The wipe-vs-preserve tension:** if the device might be recovered and you'd want forensics, an immediate wipe destroys that. In practice, for a lost consumer laptop, wipe immediately — recovery is rare and data protection matters more. For a suspected targeted theft where you may pursue it legally, discuss with Legal before wiping.

## Step 4 — Verification
- [ ] Encryption status **evidenced**, not assumed (recovery key escrow, Intune report, or TVM assessment attached)
- [ ] Post-loss activity check run (Q16.1) and result recorded
- [ ] Owner's sessions revoked and password reset
- [ ] Remote wipe issued (recorded even if pending, with the pending status noted)
- [ ] Device object disabled / marked non-compliant
- [ ] Certificates, SSH keys, and tokens rotated
- [ ] BitLocker recovery key rotated
- [ ] Local data inventory attempted — Known Folder Move status checked
- [ ] Privileged access reviewed and rotated if applicable
- [ ] Legal briefed for the notification determination, with the encryption evidence
- [ ] CMDB updated; police reference recorded if applicable

## Step 5 — Follow-up findings worth raising
Every lost-device incident tends to reveal one of these. Raise it rather than closing quietly:
- Encryption not actually enabled on some fleet segment → compliance report and remediation
- OneDrive Known Folder Move not deployed → local data exposure that didn't need to exist
- Devices not checking in for months → visibility gap; you can't wipe what never connects
- No documented process for asset retention during investigations
- Users storing sensitive extracts locally → data handling training or a tooling fix

## Step 6 — ServiceNow
Category `Lost/Stolen Device`. Link the asset CI and update its state.
Attach the encryption evidence — it is the single most important artifact for the breach determination.
Close notes: encryption status with evidence, post-loss activity result, actions taken, wipe status (completed vs pending), Legal determination.
