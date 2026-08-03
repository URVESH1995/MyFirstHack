# SOC Incident Response Playbooks
### Tooling: Splunk Cloud (+ Enterprise Security) · Microsoft Defender XDR · ServiceNow (SecOps / SIR)

> **How to use this:** Section 1–3 are the common framework that applies to every incident. Section 4 contains the per-incident-type playbooks. Section 5 is a tool cheat-sheet. All SPL and KQL are starting points — index names, sourcetypes and field names must be adjusted to your environment (check your CIM data models and `| metadata` output first).

---

## 1. The common response lifecycle (NIST 800-61 mapped to your tools)

| Phase | What you do | Splunk Cloud | Defender XDR | ServiceNow |
|---|---|---|---|---|
| **1. Detect** | Alert fires or hunt finds something | Correlation search → Notable in Incident Review; RBA risk score threshold | Incident created from correlated alerts (MDE/MDO/MDI/MDCA) | SIR ticket auto-created via integration |
| **2. Triage** | Is it real? How bad? | Drill down on notable, pivot on asset/identity | Incident graph, alert story, Advanced Hunting | Set Category, Priority, Assignment group |
| **3. Investigate** | Scope it — how many hosts, users, how long | Historical search across 30–90 days | Device/user timeline, `DeviceEvents` tables | Log every finding as a Work Note (timestamped) |
| **4. Contain** | Stop the bleeding | Push blocklists via Adaptive Response | Isolate device, Contain user, block IoC | Move SIR state → **Contain** |
| **5. Eradicate** | Remove the foothold | Verify no further hits on IoCs | Quarantine file, AV scan, remove persistence | State → **Eradicate** |
| **6. Recover** | Restore to normal | Re-enable monitoring, tune the rule | Release from isolation, unblock user | State → **Recover** |
| **7. Post-incident** | Lessons learned | New/updated correlation search | New custom detection rule | Post Incident Review, close with resolution code |

**Golden rules**
- Never contain before you've captured volatile evidence (memory, running processes, network connections) *unless* it's active ransomware or active exfil — then containment wins.
- Every action gets a work note in ServiceNow with UTC timestamp, analyst name, and the tool used. If it isn't in the ticket, it didn't happen.
- Do not touch a device that may become a legal/HR matter. Escalate to IR lead + Legal first.

---

## 2. Severity / priority matrix and SLA

| Priority | Definition | Examples | Ack SLA | Containment SLA |
|---|---|---|---|---|
| **P1 – Critical** | Active, spreading, or affecting critical assets / crown-jewel data | Ransomware encryption in progress, domain admin compromise, confirmed data exfil, DC compromise | 15 min | 1 hour |
| **P2 – High** | Confirmed compromise, contained scope | Single-host malware with C2, BEC on one mailbox, successful phish credential entry | 30 min | 4 hours |
| **P3 – Medium** | Suspicious, unconfirmed, or blocked-but-notable | Blocked malware, password spray with no success, policy violation | 4 hours | 24 hours |
| **P4 – Low** | Informational, hygiene | Unauthorized software, EICAR test, single failed-login burst | 1 business day | Best effort |

**Priority = Impact × Urgency.** In ServiceNow SIR set both fields; don't hand-set Priority. Escalate priority (never quietly downgrade) when scope grows — document the reason.

---

## 3. Universal triage checklist (run this on every notable/incident)

1. **De-duplicate** — is there an existing SIR for this asset/user/IoC? Link as child, don't open a duplicate.
2. **Identify the asset** — owner, business criticality, environment (prod/dev), internet-facing? (Splunk Asset & Identity framework / ServiceNow CMDB CI).
3. **Identify the identity** — role, privilege level, is it a service account, is it in a privileged group?
4. **Confirm the detection logic** — read the correlation search. What actually triggered? Known FP pattern?
5. **Establish a timeline** — first seen, last seen. Widen the search window to at least 30 days.
6. **Look for the "-1"** — what happened *before* the alert? Initial access is almost never the alerting event.
7. **Look for the "+1"** — did anything happen *after*? Persistence, lateral movement, new accounts.
8. **Check blast radius** — same IoC on other hosts? Same sender to other recipients? Same source IP against other accounts?
9. **Decide:** True Positive / False Positive / Benign True Positive (real but authorized). Record which, with evidence.
10. **Handover note** if the shift is ending: what's confirmed, what's pending, what's the next action.

---

## 4. Incident playbooks

---
### PB-01 · Phishing / Malicious Email
**Default priority:** P3 → P2 if credentials entered or attachment executed
**Detection sources:** Defender for Office 365 alerts, user reports (Report Phishing button), Splunk correlation on message trace + proxy

**Triage**
- Get the `NetworkMessageId` and pivot in Advanced Hunting:
```kql
EmailEvents
| where Timestamp > ago(14d)
| where SenderFromAddress =~ "attacker@bad-domain.com" or Subject has "Payment Overdue"
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderIPv4, RecipientEmailAddress,
          Subject, DeliveryAction, DeliveryLocation, ThreatTypes
| join kind=leftouter (EmailUrlInfo | project NetworkMessageId, Url) on NetworkMessageId
```
- Did anyone **click**?
```kql
UrlClickEvents
| where Timestamp > ago(14d)
| where Url has "bad-domain.com"
| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, IPAddress
```
- Did anyone **submit credentials**? Check for a sign-in from the phishing infrastructure IP/ASN shortly after the click:
```
index=azure_ad sourcetype="azure:aad:signin" user="victim@corp.com"
| stats count min(_time) max(_time) values(appDisplayName) by src_ip, user_agent, location.countryOrRegion, status.errorCode
| sort - count
```
- Was an **attachment** opened?
```kql
EmailAttachmentInfo
| where NetworkMessageId == "<id>"
| project FileName, SHA256, FileType, ThreatTypes
```
Then check `DeviceFileEvents` / `DeviceProcessEvents` for that SHA256.

**Containment**
- Defender XDR → Explorer → select all matching messages → **Soft delete** / **Move to deleted items** (purges from all mailboxes tenant-wide).
- Add sender domain, URLs and file hash to **Tenant Allow/Block List** and MDE **Indicators**.
- Block the URL/domain at the proxy and DNS (push via Splunk Adaptive Response if you have the integration).
- If credentials entered: revoke sessions + force password reset (see PB-04) — treat as account compromise.
- If attachment executed: isolate the device (see PB-02).

**Eradication & Recovery**
- Confirm zero remaining copies: re-run the `EmailEvents` query filtered to `DeliveryLocation == "Inbox"`.
- Check mailbox rules created after the click (`ExchangeAdminEvents` / `New-InboxRule`) — classic BEC follow-on.
- Submit the sample to Microsoft (Submissions portal) for detection improvement.
- User awareness follow-up; if repeat clicker, flag to training.

**ServiceNow:** Category `Phishing`; attach the .msg/EML as evidence; list all affected recipients in the Affected Users related list.

**Common FPs:** Marketing bulk mail, internal red team / phishing simulation (check with your awareness team first — cross-reference the simulation sender list), legitimate DocuSign/Adobe notifications.

---
### PB-02 · Malware / Endpoint Detection
**Default priority:** P3 if blocked/quarantined, P2 if executed, P1 if on a server or spreading

**Triage**
```kql
DeviceProcessEvents
| where DeviceName == "HOST01" and Timestamp between (datetime(2026-07-30) .. datetime(2026-08-01))
| project Timestamp, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```
- Determine **execution status**: did Defender block pre-execution, or did it run? (Alert says "Prevented" vs "Detected".)
- Get parent process chain — where did it come from? Email, browser download, USB, network share?
- Check for network connections:
```kql
DeviceNetworkEvents
| where DeviceName == "HOST01" and InitiatingProcessSHA256 == "<sha256>"
| project Timestamp, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName
```
- Hunt the hash fleet-wide:
```kql
union DeviceFileEvents, DeviceProcessEvents, DeviceImageLoadEvents
| where SHA256 == "<sha256>"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceName
```

**Containment**
- Defender → Device page → **Isolate device** (Full isolation; use Selective only if the user needs Teams contact).
- **Collect investigation package** *before* remediation — this is your evidence.
- **Stop and quarantine file** across the fleet.
- Add SHA256 + C2 IPs/domains as **Indicators** (Block and remediate).
- Block C2 IoCs at firewall/proxy; create a Splunk alert on any future hit.

**Eradication & Recovery**
- Full AV scan; check persistence: `DeviceRegistryEvents` on Run keys, `DeviceEvents` with `ActionType == "ScheduledTaskCreated"`, services, WMI subscriptions, startup folders.
- Rotate any credentials that were used or cached on the host.
- **Reimage** if: kernel-level/rootkit, unknown-provenance implant, or you can't confidently prove full removal. Reimaging is cheaper than a second incident.
- Release from isolation only after clean scan + no C2 for 24h. Monitor the host for 7 days.

**Common FPs:** Pentest tooling, admin scripts (PsExec, nircmd), packed installers, crypto-miner FP on legitimate compute, dual-use tools like Advanced IP Scanner used by real IT.

---
### PB-03 · Ransomware
**Default priority:** P1 always. Wake people up.

**Immediate actions (first 15 minutes — containment beats evidence here)**
1. **Isolate every affected device** in Defender. Bulk-select from the incident page.
2. Disable the compromised accounts' sign-in and revoke sessions in Entra ID.
3. Notify: IR lead, CISO, IT ops (to protect backups), Legal, Comms. Start the crisis bridge.
4. **Protect backups immediately** — verify immutability, take the backup network offline if needed. Attackers target backups first.
5. Do **not** power off encrypted machines (loses memory/keys); isolate at the network layer instead.

**Scoping**
```kql
DeviceProcessEvents
| where Timestamp > ago(2d)
| where FileName in~ ("vssadmin.exe","wmic.exe","bcdedit.exe","wbadmin.exe","cipher.exe")
| where ProcessCommandLine has_any ("delete shadows","shadowcopy delete","recoveryenabled no",
        "bootstatuspolicy ignoreallfailures","delete catalog","/w")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```
Mass file modification:
```kql
DeviceFileEvents
| where Timestamp > ago(1d) and ActionType == "FileRenamed"
| summarize FileCount=count(), Extensions=make_set(tostring(split(FileName,".")[-1]), 10)
    by DeviceName, InitiatingProcessFileName, bin(Timestamp, 5m)
| where FileCount > 200
```
File share impact in Splunk:
```
index=wineventlog EventCode=5145 OR EventCode=4663
| stats dc(Object_Name) as files_touched by Account_Name, Source_Address, host
| where files_touched > 500
```
Identify the **initial access vector** — almost always: exposed RDP/VPN, phish, or exploited edge device. You must find this or it recurs.

**Eradication & Recovery**
- Rebuild from known-good images. Do not decrypt-in-place on a machine you haven't rebuilt.
- Reset **all** privileged credentials, plus the KRBTGT account twice (with the required interval between resets) if AD was compromised.
- Restore data from verified-clean backups; scan restored data before reconnecting.
- Staged recovery: DCs → core infra → business-critical → general fleet.
- Ransom payment decisions are business/legal, never SOC. Document but don't advise.

**ServiceNow:** P1 SIR, engage Major Incident process, run the parallel comms task list. Track regulatory notification clocks (GDPR 72h, and any sector-specific requirements — Legal owns this determination).

---
### PB-04 · Compromised Account / Credential Compromise
**Default priority:** P2, P1 if privileged account

**Triage**
```
index=azure_ad sourcetype="azure:aad:signin" userPrincipalName="victim@corp.com" earliest=-30d
| eval risk=if(riskLevelDuringSignIn IN ("high","medium"),"RISKY","normal")
| stats count values(appDisplayName) as apps values(user_agent) as agents
    by src_ip, location.city, location.countryOrRegion, status.errorCode, risk
| sort - count
```
Look for: sign-in from unusual geo/ASN, legacy auth protocols, new device registration, MFA method added, token replay (same session token from two IPs).
```kql
IdentityLogonEvents
| where AccountUpn =~ "victim@corp.com" and Timestamp > ago(30d)
| summarize by Timestamp, DeviceName, IPAddress, LogonType, Application, ActionType
```
Post-compromise actions to check for:
- New inbox rules (auto-forward / delete to hide replies)
- Mailbox delegation or permission grants
- OAuth app consent grants (illicit consent grant attack)
- MFA method registered by the attacker
- Sent items: internal spear-phish, invoice fraud
- Sharing links created in SharePoint/OneDrive
```
index=o365 sourcetype="o365:management:activity" Operation IN ("New-InboxRule","Set-InboxRule","Add-MailboxPermission","Consent to application","Add member to role","UpdateUser")
| table _time, UserId, Operation, ObjectId, ClientIP, Parameters
```

**Containment**
- Entra ID: **Revoke all sessions**, force password reset, require MFA re-registration (delete attacker-registered methods), **block sign-in** if needed.
- Defender XDR: **Contain user** to limit lateral movement from that identity.
- Remove malicious inbox rules, revoke OAuth consents, remove attacker-added delegations.
- Block attacker IPs; check if the same IP hit other accounts (see PB-05).

**Recovery**
- Re-enable with a fresh password delivered out-of-band; verify the user's own MFA is re-enrolled.
- If the user has admin roles: review all changes made under that identity during the compromise window.
- Check whether the same password is reused elsewhere (VPN, SaaS, local admin).

**Common FPs:** VPN/travel, corporate proxy egress in another country, new phone re-enrolling MFA, shared service accounts (fix the underlying practice).

---
### PB-05 · Brute Force / Password Spray / MFA Fatigue
**Default priority:** P3, P2 on any success

**Detection**
```
index=azure_ad sourcetype="azure:aad:signin" status.errorCode IN (50126, 50053, 50055, 50056)
| bucket _time span=1h
| stats dc(userPrincipalName) as unique_users count as attempts values(status.errorCode) as codes by src_ip, _time
| where unique_users > 10 OR attempts > 100
| sort - unique_users
```
*(50126 = invalid credentials, 50053 = smart lockout, 50055 = expired password)*

Then check for **any success from the same source**:
```
index=azure_ad sourcetype="azure:aad:signin" src_ip="1.2.3.4" status.errorCode=0
| table _time, userPrincipalName, appDisplayName, authenticationRequirement, conditionalAccessStatus
```
On-prem / Windows:
```
index=wineventlog EventCode=4625
| stats count dc(Account_Name) as accounts by Source_Network_Address, host
| where count > 50
```
MFA fatigue (repeated push denials then an approval):
```
index=azure_ad sourcetype="azure:aad:signin" status.errorCode IN (500121, 0)
| transaction userPrincipalName maxspan=15m
| where mvcount(status.errorCode) > 5 AND match(mvjoin(status.errorCode,","), "0$")
```

**Containment**
- Block source IP/ASN at the edge and in Conditional Access named locations.
- If success: full PB-04 on that account.
- Enable/tighten: smart lockout, MFA number matching, block legacy authentication, risk-based CA policies.
- Check for spray success against accounts without MFA — that gap list is an action item.

---
### PB-06 · Command & Control / Beaconing / Suspicious Outbound
**Default priority:** P2 → P1 if on a server or multiple hosts

**Detection (Splunk — jitter/regularity based)**
```
index=firewall OR index=proxy action=allowed
| sort 0 src_ip, dest_ip, _time
| streamstats current=f last(_time) as prev_time by src_ip, dest_ip
| eval delta = _time - prev_time
| stats count as connections avg(delta) as avg_interval stdev(delta) as jitter
        sum(bytes_out) as total_out dc(_time) as distinct_times by src_ip, dest_ip, dest_port
| where connections > 30 AND jitter < 30 AND avg_interval > 30
| sort jitter
```
Rare-destination / newly-seen domain:
```
index=proxy earliest=-7d
| stats dc(src_ip) as clients count min(_time) as first_seen by dest_host
| where clients <= 2 AND count > 20 AND first_seen > relative_time(now(), "-3d")
```
DNS tunneling:
```
index=dns
| eval qlen = len(query), sub = mvindex(split(query,"."), 0)
| stats count avg(qlen) as avg_len dc(query) as unique_queries sum(qlen) as volume by src_ip, domain
| where unique_queries > 500 AND avg_len > 45
```
**Defender side**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d) and RemoteIP == "1.2.3.4"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl
```
Identify the **process** making the connection — that's your malware. If it's a legitimate binary (rundll32, regsvr32, msbuild, mshta), suspect LOLBin abuse → PB-07.

**Containment:** Isolate host, block IoC at all egress points, add Defender indicator, sinkhole the domain, then PB-02 eradication on the host.

**Common FPs:** Software update checkers, telemetry/analytics SDKs, monitoring agents, certificate revocation checks, VoIP keepalives. Build an allowlist of known-good beaconers to keep this rule usable.

---
### PB-07 · Suspicious PowerShell / Living-off-the-Land
**Default priority:** P2

**Detection**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe",
                      "rundll32.exe","regsvr32.exe","certutil.exe","bitsadmin.exe","msbuild.exe","installutil.exe")
| where ProcessCommandLine has_any ("-enc","-EncodedCommand","FromBase64String","IEX","Invoke-Expression",
        "DownloadString","DownloadFile","Invoke-WebRequest","-nop","-noni","-w hidden","hidden",
        "bypass","New-Object Net.WebClient","curl ","-urlcache","javascript:","scrobj.dll")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```
Splunk (Sysmon EID 1 / Windows 4688):
```
index=sysmon EventCode=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| eval cmd=lower(CommandLine)
| search cmd IN ("*-enc*","*frombase64string*","*downloadstring*","*-w hidden*","*bypass*")
| table _time, host, User, ParentImage, CommandLine
```
**Triage:** Decode any base64 (`-enc`) payload in a safe environment and read it — this tells you the intent immediately. Check the parent process: Office app parent = phishing macro; `services.exe` parent = persistence; `wmiprvse.exe` parent = remote execution.

**Containment / Eradication:** As PB-02. Additionally check for AMSI bypass attempts, script block logging tampering, and disabled Defender features (`DeviceEvents | where ActionType has "TamperingAttempt"`).

**Common FPs:** SCCM/Intune scripts, admin automation, software deployment. Baseline your own admin tooling and exclude by *signed script path + expected parent*, not by process name alone.

---
### PB-08 · Lateral Movement
**Default priority:** P1 (means an attacker is already inside and expanding)

**Detection**
```kql
DeviceLogonEvents
| where Timestamp > ago(3d) and LogonType in ("Network","RemoteInteractive")
| summarize Hosts=dcount(DeviceName), HostList=make_set(DeviceName, 20), Logons=count()
    by AccountName, RemoteIP
| where Hosts > 5
| order by Hosts desc
```
Pass-the-hash / overpass-the-hash indicators (Windows 4624 with LogonType 3 + NTLM on a Kerberos environment):
```
index=wineventlog EventCode=4624 Logon_Type=3 Authentication_Package=NTLM
| stats dc(host) as targets count by Account_Name, Source_Network_Address
| where targets > 3
```
Remote service creation / PsExec:
```kql
DeviceEvents
| where ActionType in ("ServiceInstalled","ScheduledTaskCreated")
| project Timestamp, DeviceName, AccountName, AdditionalFields
```
```
index=wineventlog EventCode=7045
| table _time, host, Service_Name, Service_File_Name, Account_Name
```
Also hunt: WMI remote exec (`wmiprvse.exe` spawning processes), WinRM (5985/5986), SMB admin share writes (`ADMIN$`, `C$`), RDP internal spread (3389 east-west), DCSync (MDI alert), Kerberoasting (4769 with RC4 encryption for many SPNs).

**Containment**
- Isolate **all** touched hosts simultaneously, not one at a time — sequential isolation lets the attacker relocate.
- Disable and reset the compromised accounts; **Contain user** in Defender XDR.
- Block the attacker's internal source IPs at network segmentation points.
- If any tier-0 asset (DC, PKI, backup server, identity provider) is involved → treat as full domain compromise, engage IR retainer, plan for AD recovery.

**Eradication:** Reset all credentials in the compromise chain, including service accounts and local admin (deploy LAPS if not present). Hunt persistence on every touched host.

---
### PB-09 · Privilege Escalation / Suspicious Admin Activity
**Default priority:** P2 → P1 for tier-0 groups

**Detection**
```
index=wineventlog EventCode IN (4728, 4732, 4756, 4720, 4672, 4704)
| table _time, host, Subject_Account_Name, Member_Name, Group_Name, EventCode
```
Entra ID role assignments:
```
index=azure_ad sourcetype="azure:aad:audit" operationName IN ("Add member to role","Add eligible member to role","Add app role assignment")
| table _time, initiatedBy.user.userPrincipalName, targetResources{}.userPrincipalName, targetResources{}.modifiedProperties{}.newValue
```
```kql
IdentityDirectoryEvents
| where ActionType in ("Group Membership changed","Account Password changed","SAM Account Name changed")
| project Timestamp, ActionType, AccountName, TargetAccountUpn, AdditionalFields
```
**Triage questions:** Was there a change ticket? Did the *actor* have the authority to grant this? Was the grant made outside business hours? Is the target a service account or a dormant account?

**Containment:** Reverse the unauthorized grant, disable the account that made it (pending confirmation with the account owner via a known-good channel — not email, which may be compromised), review everything that account did.

**Prevention follow-up:** PIM/JIT for privileged roles, approval workflows, alerting on all tier-0 group changes with no matching change record.

---
### PB-10 · Data Exfiltration / Insider Threat
**Default priority:** P1 if confirmed sensitive data left; P2 for suspicious volume
> Loop in **HR and Legal before** you investigate a named employee. Follow your internal investigation authorization process. Evidence handling matters here more than anywhere else.

**Detection**
```
index=proxy earliest=-7d
| stats sum(bytes_out) as bytes_out dc(dest_host) as destinations by user, dest_host
| eval GB_out = round(bytes_out/1024/1024/1024, 2)
| where GB_out > 1
| sort - GB_out
```
Personal cloud storage / unsanctioned SaaS:
```
index=proxy dest_host IN ("*.dropbox.com","*.wetransfer.com","*mega.nz*","*drive.google.com*","*pcloud*")
| stats sum(bytes_out) as bytes_out count by user, dest_host
| where bytes_out > 104857600
```
Endpoint side:
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated" and FolderPath has_any ("\\Removable", "E:\\", "F:\\")
| summarize Files=count(), TotalMB=sum(FileSize)/1024/1024 by DeviceName, InitiatingProcessAccountName
| where TotalMB > 100
```
Mass SharePoint/OneDrive download and external sharing:
```
index=o365 Operation IN ("FileSyncDownloadedFull","FileDownloaded","AnonymousLinkCreated","SharingInvitationCreated","AddedToSecureLink")
| stats count dc(SourceFileName) as files by UserId, Operation, ClientIP
| where files > 100
```
Also check: printing volume, email to personal addresses with attachments, git repo cloning, DLP policy hits (Purview), archive creation before upload (`.7z`/`.zip` of a share).

**Containment**
- Preserve first: **collect investigation package**, preserve mailbox (litigation hold), snapshot the endpoint. Do not let the user wipe the device.
- Block the destination; revoke external sharing links; disable the account if authorized to do so.
- If it's a departing employee, coordinate timing with HR — do not tip them off unilaterally.

**Reporting:** Determine data classification and whether it's a notifiable breach. Legal owns notification; you own the factual timeline. Give them: what data, how much, when, where it went, and how you know.

---
### PB-11 · Web Application Attack / Internet-Facing Exploitation
**Default priority:** P2 → P1 if exploitation succeeded

**Detection**
```
index=web sourcetype=access_combined
| eval decoded = urldecode(uri_query)
| eval decoded = lower(decoded)
| search decoded IN ("*union*select*","*' or '1'='1*","*sleep(*","*benchmark(*","*<script*",
                     "*onerror=*","*../../*","*etc/passwd*","*cmd.exe*","*base64_decode*","*${jndi:*")
| stats count values(uri_path) as paths values(status) as statuses by clientip, useragent
| sort - count
```
Focus on **successful** exploitation — a 200 with an unusual response size after a string of 400/500s is the signal:
```
index=web sourcetype=access_combined clientip="1.2.3.4"
| stats count by status, uri_path, bytes
| sort - count
```
Then check the server for post-exploitation:
```kql
DeviceProcessEvents
| where DeviceName == "WEBSRV01"
| where InitiatingProcessFileName in~ ("w3wp.exe","httpd.exe","nginx.exe","java.exe","tomcat*.exe")
| where FileName in~ ("cmd.exe","powershell.exe","bash","sh","whoami.exe","net.exe")
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName
```
A web server process spawning a shell = **confirmed compromise, escalate to P1.**

Webshell hunt:
```kql
DeviceFileEvents
| where FolderPath has_any ("inetpub\\wwwroot","\\webapps\\","/var/www/")
| where FileName endswith_any (".aspx",".asp",".php",".jsp",".jspx")
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, SHA256
```

**Containment:** WAF block rule / IP block, take the app offline if actively exploited, isolate the server, remove webshells, patch the vulnerability. Rotate any credentials or secrets stored on/accessible to that host (DB creds, API keys, cloud instance metadata credentials).

---
### PB-12 · Vulnerability Exploitation of Unpatched Systems (incl. edge devices)
**Default priority:** P1 for internet-facing, P2 internal

**Steps**
1. Confirm the CVE and whether the asset is actually vulnerable (version check, not just scanner output). Use Defender Vulnerability Management → Software inventory / Weaknesses.
2. Determine exposure: internet-facing? authenticated pre-req? PoC public? Actively exploited in the wild (CISA KEV)?
3. Hunt for exploitation attempts and success in Splunk (see PB-11 pattern for the specific CVE's indicators).
4. **Emergency patch or compensating control**: WAF rule, disable the vulnerable feature/module, network ACL, take offline.
5. If exploitation is confirmed, this is a compromise — pivot to PB-11/PB-02, assume credential theft on the device.
6. Fleet-wide sweep:
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId == "CVE-XXXX-XXXXX"
| project DeviceName, SoftwareName, SoftwareVersion, VulnerabilitySeverityLevel
```
7. Track remediation in ServiceNow as a Change + a Vulnerability Response record; don't close the SIR until patching is verified.

---
### PB-13 · Denial of Service / DDoS
**Default priority:** P1 if customer-facing service is degraded

**Steps**
1. Confirm it's an attack, not a capacity or code problem. Check: request rate vs. baseline, geographic distribution, request uniformity, error rates.
```
index=web sourcetype=access_combined earliest=-1h
| timechart span=1m count by status
```
```
index=web earliest=-30m | stats count by clientip | sort - count | head 50
```
2. Identify the layer: volumetric (L3/L4) vs application (L7) vs protocol.
3. Engage ISP / DDoS scrubbing provider (Azure DDoS Protection, Cloudflare, Akamai) — have these contacts pre-staged.
4. Mitigations: rate limiting, geo-blocking, CAPTCHA/JS challenge, scale out, WAF rules, drop the offending signature.
5. Watch for DDoS as a **smokescreen** — check for concurrent intrusion activity while everyone's looking at the traffic graph.
6. Comms: status page updates, exec briefing cadence.

---
### PB-14 · Cloud / SaaS Misconfiguration & Abuse
**Default priority:** P2, P1 if data publicly exposed

**Detection**
```
index=azure sourcetype="azure:activity" operationName IN ("Microsoft.Storage/storageAccounts/write","Microsoft.Authorization/roleAssignments/write","Microsoft.Network/networkSecurityGroups/securityRules/write")
| table _time, caller, operationName, resourceId, properties.statusCode
```
Look for: public storage buckets/blobs, `0.0.0.0/0` inbound rules, disabled logging, new service principals with broad consent, key vault access policy changes, resource creation in unusual regions (crypto-mining).
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType has_any ("Add service principal","Add OAuth2PermissionGrant","Update application","Remove policy")
| project Timestamp, AccountDisplayName, ActionType, IPAddress, ObjectName, RawEventData
```
**Containment:** Revert the misconfiguration, revoke exposed keys/tokens, check access logs for whether anyone *used* the exposure (that determines breach vs. near-miss), remove rogue service principals.
**Follow-up:** Defender for Cloud secure score item, policy-as-code guardrail so it can't recur, and a Change ticket to explain how it got there.

---
### PB-15 · Unauthorized Software / Policy Violation / Shadow IT
**Default priority:** P4 → P3 if the software is dual-use (RMM tools, tunnelling, hacking tools)

**Detection**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("anydesk.exe","teamviewer.exe","screenconnect.exe","ngrok.exe","rustdesk.exe",
                      "tor.exe","psexec.exe","mimikatz.exe","advanced_ip_scanner.exe","rclone.exe")
| summarize FirstSeen=min(Timestamp), Count=count() by DeviceName, AccountName, FileName
```
> **Note:** unauthorized RMM tools (AnyDesk, ScreenConnect, ngrok) and `rclone` are heavily used by real intruders. Treat an unexplained RMM install as **P2 suspected intrusion** until you can attribute it to a named human with a reason.

**Steps:** Confirm business justification with the user's manager → if unauthorized, remove software, add to app control blocklist (WDAC/AppLocker), document policy violation to HR per your AUP, offer a sanctioned alternative.

---
### PB-16 · Lost / Stolen Device
**Default priority:** P2, P1 if it held sensitive data unencrypted

**Steps**
1. Confirm encryption status (BitLocker/FileVault) — encrypted-at-rest and powered-off substantially reduces impact. Record the evidence of encryption state.
2. Intune: **remote wipe** (or retire for BYOD). Mark device as non-compliant.
3. Entra ID: revoke all sessions for the user, disable the device object, force password reset.
4. Defender: check last-seen activity for any post-loss access.
5. Determine what data was on it; assess notification obligation with Legal.
6. Police report if required by policy/insurance; asset record update in CMDB.

---
### PB-17 · Third-Party / Supply Chain Compromise
**Default priority:** P1 if the vendor has network access or holds your data

**Steps**
1. Establish what access the vendor has: VPN, VPN accounts, SaaS integration, OAuth app, API keys, remote access tooling, hardware.
2. **Suspend the vendor's access** pending assessment (accounts, tokens, site-to-site tunnel).
3. Hunt for activity from vendor accounts/IPs across the exposure window:
```
index=* (user IN ("vendor_svc*","*@vendor.com") OR src_ip IN (<vendor ranges>))
| stats count values(action) as actions by user, src_ip, index, sourcetype
```
4. Rotate all shared credentials, API keys and certificates.
5. If it's a software supply chain issue (compromised update/library), hunt the affected version fleet-wide, block the vendor's update channel temporarily, and follow the vendor's IoC list.
6. Demand written vendor IR updates; track in ServiceNow with the vendor record linked.

---

## 5. Tool cheat-sheet

### Microsoft Defender XDR — response action reference
| Need | Action | Where |
|---|---|---|
| Cut a host off the network | **Isolate device** (Full / Selective) | Device page → Actions |
| Preserve evidence | **Collect investigation package** | Device page → Actions |
| Kill and remove a file everywhere | **Stop and quarantine file** | File page → Actions |
| Block a hash/IP/URL/cert | **Indicators** → Block and remediate | Settings → Endpoints → Indicators |
| Limit only risky apps | **Restrict app execution** | Device page → Actions |
| Deep manual work on a host | **Live Response** (`getfile`, `putfile`, `run`, `remediate`, `processes`, `connections`) | Device page → Initiate Live Response |
| Stop a compromised identity spreading | **Contain user** | Incident/user page |
| Contain an unmanaged/rogue device | **Contain device** | Device page |
| Remove phishing from all mailboxes | **Soft delete / Purge** via Explorer | Defender portal → Explorer |
| Turn a hunt into a detection | **Create custom detection rule** from Advanced Hunting query | Advanced Hunting → Save → Create detection rule |

**Key Advanced Hunting tables:** `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceLogonEvents`, `DeviceEvents`, `DeviceImageLoadEvents`, `EmailEvents`, `EmailUrlInfo`, `EmailAttachmentInfo`, `UrlClickEvents`, `IdentityLogonEvents`, `IdentityDirectoryEvents`, `IdentityQueryEvents`, `CloudAppEvents`, `AlertEvidence`, `AlertInfo`, `DeviceTvmSoftwareVulnerabilities`.

### Splunk Cloud / ES
- **Incident Review** is your queue. Own the notable (assign to yourself), set status: New → In Progress → Pending → Resolved → Closed.
- **Adaptive Response Actions**: use these to push containment from Splunk (Defender isolate, firewall block, ServiceNow ticket creation, notification).
- **Risk-Based Alerting**: prefer risk score accumulation over single-event alerts for noisy detections. Tune `risk_object` and `risk_object_type` on your correlation searches.
- **Asset & Identity Framework**: keep `assets.csv` / `identities.csv` current — it's what turns an IP into "the CFO's laptop". Sync from ServiceNow CMDB.
- **Tuning**: use throttling (window + fields) and suppression rather than deleting rules. Every FP closure should end with either a tuning change or a documented reason not to tune.
- **Useful triage searches:**
```
| tstats count where index=* by index, sourcetype    ``` (what data do I actually have?)
```
```
| rest /services/saved/searches | search action.correlationsearch.enabled=1 | table title, cron_schedule, search
```

### ServiceNow SecOps (SIR)
**State flow:** Draft → Analysis → Contain → Eradicate → Recover → Review → Closed.

Fields to fill properly every time:
- **Category / Subcategory** (drives reporting and playbook automation)
- **Business impact / Priority** (set Impact + Urgency, let Priority calculate)
- **Affected CIs** (link real CMDB records — this is how you get blast-radius reporting)
- **Affected Users**
- **Work notes** — the running investigation log, UTC timestamps
- **Attachments** — investigation package, screenshots, EML, IoC list
- **Resolution code + Close notes** — True Positive / False Positive / Benign, root cause, what fixed it
- **Post Incident Review** — mandatory for P1/P2

**Automation worth building:** Splunk notable → SIR auto-create with dedupe on IoC; SIR state change → Defender action via Flow Designer; auto-enrich with CMDB owner + criticality on creation.

---

## 6. Evidence handling
- Collect in order of volatility: memory → network connections → running processes → disk → logs → archives.
- Hash every artifact (SHA256) at collection; record hash in the ticket.
- Keep a chain-of-custody entry for anything that may go to Legal/HR/law enforcement: who collected, when (UTC), from where, hash, where it's stored.
- Store evidence in a restricted location, not on a shared drive or in the ticket body.
- Retention: align with your legal hold policy; default 1 year minimum for P1/P2.

---

## 7. Escalation matrix (fill in your own names)

| Trigger | Escalate to |
|---|---|
| Any P1 | SOC Lead + CISO immediately, phone not email |
| Tier-0 asset involved (DC, PKI, backup, IdP) | IR Lead + Infrastructure Lead |
| Confirmed data loss / PII | Legal + DPO + Comms |
| Employee-related investigation | HR + Legal before any action |
| Suspected nation-state / advanced actor | CISO + external IR retainer |
| Regulatory notification clock started | Legal (owns the decision and the clock) |
| Vendor/third-party involved | Vendor Manager + Legal |

---

## 8. Metrics to track (per playbook)
MTTD, MTTA, MTTR, containment time, dwell time, FP rate per correlation search, escalation accuracy, SLA compliance %, % of incidents auto-enriched, coverage gaps found. Review monthly; the FP rate per rule is your most actionable number.

---

## 9. Detection engineering feedback loop
Every closed incident must answer three questions in the Post Incident Review:
1. **Could we have detected this earlier?** → new correlation search / Defender custom detection rule.
2. **Could we have prevented it?** → hardening or policy change (raise as a Change/Problem record).
3. **Was the playbook right?** → update this document, version it, note the change date.

Map every detection you build to **MITRE ATT&CK** and maintain a coverage heatmap (Defender has a built-in view; DeTT&CT or ATT&CK Navigator for Splunk-side coverage). Gaps in Initial Access, Credential Access and Exfiltration usually hurt the most.

---
*Document owner: SOC. Review cadence: quarterly, or after any P1.*
