# ENDPOINT RUNBOOKS
### PB-02 Malware · PB-03 Ransomware · PB-07 LOLBin & Suspicious Scripting · PB-15 Unauthorized RMM

**Tools:** Microsoft Defender for Endpoint · Splunk Cloud ES · ServiceNow SecOps
**Portal:** `security.microsoft.com` (menu names change; use the portal search bar if a path doesn't match)

---
---

# PB-02 · Malware / Endpoint Detection

**Default priority:** P3 if blocked pre-execution · P2 if executed · P1 if on a server, or on 3+ hosts, or credential-theft tooling

**Detection sources:** MDE alert, Splunk correlation (`Endpoint - Suspicious Encoded PowerShell`, `Office Application Spawning Script Interpreter`), user report, threat hunt.

---

## Step 1 — Establish execution status (this drives everything)

**Click path:** `security.microsoft.com` → **Incidents & alerts** → **Alerts** → open alert → read the **Detection status** field.

| Alert says | Meaning | Branch |
|---|---|---|
| **Prevented / Blocked** | Never executed. AV or ASR stopped it. | Branch A |
| **Detected** | It ran. Defender saw it after the fact. | Branch B |
| **Remediated / Quarantined** | It ran, then Defender cleaned it. Still executed. | Branch B |
| **Automated investigation: no threats found** | Do not trust blindly. Verify manually. | Branch B until proven otherwise |

> The single most common triage error is treating "Remediated" as "never ran." Remediation happens *after* execution. If it executed, credentials on that host are potentially compromised and you must check for persistence and C2.

---

## Step 2 — Decision tree

```
Malware alert
│
├─ BRANCH A: Prevented pre-execution
│   → P3. Verify no other copies of the hash landed (Q2.3).
│   → Identify delivery vector (email → PB-01, web → check proxy, USB → check DeviceEvents).
│   → Add hash to Indicators. Close.
│   → NO isolation, NO credential rotation needed.
│
└─ BRANCH B: Executed
    │
    ├─ Q: Did it establish network communication? (Q2.4)
    │   ├─ NO → P2. Isolate, collect package, scan, check persistence, close.
    │   └─ YES → C2 confirmed. Escalate P2→P1 consideration. Also run PB-06.
    │
    ├─ Q: Is the hash on more than one host? (Q2.3)
    │   ├─ 1 host  → contained scope, P2
    │   ├─ 2-3     → P2, treat as campaign, isolate all
    │   └─ 4+      → P1. Likely automated spread or common delivery vector. Find the vector first.
    │
    ├─ Q: What class of malware?
    │   ├─ Adware / PUP / coin miner          → P3, clean, no credential rotation
    │   ├─ Infostealer (Redline, Lumma, etc.) → P2. ASSUME ALL BROWSER-SAVED AND CACHED
    │   │                                        CREDENTIALS ARE STOLEN. Force reset for the
    │   │                                        user + any account they had saved. This is the
    │   │                                        step most often skipped and it causes the
    │   │                                        follow-on incident 3 weeks later.
    │   ├─ Credential dumper (LSASS access)   → P1. Rotate everything on the host including
    │   │                                        cached domain creds and local admin. Run PB-08.
    │   ├─ Initial-access loader (Qakbot-like,
    │   │   IcedID, Pikabot, Latrodectus,
    │   │   Bumblebee, SocGholish)            → P1. These are ransomware precursors sold to
    │   │                                        affiliates. Assume a human operator will
    │   │                                        follow within hours-to-days. Hunt for
    │   │                                        lateral movement (PB-08) immediately.
    │   ├─ Ransomware                         → PB-03, P1, drop everything
    │   └─ Unknown / unclassified             → treat as the worst plausible class
    │
    └─ Q: Is it a server, DC, or tier-0 asset?
        └─ YES → P1 regardless of anything above. Engage SOC Lead + Infrastructure.
```

---

## Step 3 — Query library

**Q2.1 — Full process timeline on the host**
```kql
let target = "HOST01";
let win = 4h;
DeviceProcessEvents
| where DeviceName =~ target and Timestamp between (datetime(2026-07-30 08:00) .. datetime(2026-07-30 12:00))
| project Timestamp, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName,
          ProcessIntegrityLevel, ProcessTokenElevation
| order by Timestamp asc
```

**Q2.2 — Reconstruct the parent chain (find the delivery vector)**
```kql
let badSha = "<sha256>";
DeviceProcessEvents
| where SHA256 == badSha
| project Timestamp, DeviceName, FileName, FolderPath,
          P1=InitiatingProcessFileName, P1cmd=InitiatingProcessCommandLine,
          P2=InitiatingProcessParentFileName
| order by Timestamp asc
```
Read `P2` → `P1` → the malware. Interpretation:
- `outlook.exe` / `winword.exe` / `excel.exe` → phishing attachment, run PB-01
- `chrome.exe` / `msedge.exe` → drive-by or fake-update lure; get the URL from `DeviceNetworkEvents`
- `explorer.exe` from a removable path → USB, check `DeviceEvents` `ActionType == "UsbDriveMounted"`
- `services.exe` / `svchost.exe` → already-established persistence, this is not initial access. Widen your window.
- `wmiprvse.exe` / `WmiPrvSE` → remote execution, someone pushed this to the host. Run PB-08.
- `w3wp.exe` / `java.exe` / `nginx` → web exploitation, run PB-11, escalate P1

**Q2.3 — Fleet-wide hash sweep**
```kql
let badSha = "<sha256>";
union isfuzzy=true
  (DeviceFileEvents      | where SHA256 == badSha | project Timestamp, DeviceName, ActionType, FolderPath),
  (DeviceProcessEvents   | where SHA256 == badSha | project Timestamp, DeviceName, ActionType="Executed", FolderPath),
  (DeviceImageLoadEvents | where SHA256 == badSha | project Timestamp, DeviceName, ActionType="ImageLoaded", FolderPath)
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Actions=make_set(ActionType), Paths=make_set(FolderPath,5) by DeviceName
| order by FirstSeen asc
```

**Q2.4 — C2 / outbound communication from the malware**
```kql
let badSha = "<sha256>";
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessSHA256 == badSha
| summarize Connections=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp),
            Ports=make_set(RemotePort,10) by DeviceName, RemoteIP, RemoteUrl
| order by Connections desc
```

**Q2.5 — Persistence sweep (run all four)**
```kql
// Registry autoruns
DeviceRegistryEvents
| where Timestamp > ago(7d) and DeviceName =~ "HOST01"
| where RegistryKey has_any (@"\CurrentVersion\Run", @"\CurrentVersion\RunOnce",
        @"\Winlogon", @"\Image File Execution Options", @"\AppInit_DLLs",
        @"\Windows\CurrentVersion\Explorer\Shell Folders", @"\Policies\Explorer\Run")
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName
```
```kql
// Scheduled tasks and services
DeviceEvents
| where Timestamp > ago(7d) and DeviceName =~ "HOST01"
| where ActionType in ("ScheduledTaskCreated","ScheduledTaskUpdated","ServiceInstalled")
| project Timestamp, DeviceName, ActionType, AdditionalFields, InitiatingProcessCommandLine
```
```kql
// WMI event subscription persistence (often missed)
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType has "Wmi" or ActionType in ("WmiBindEventFilterToConsumer","WmiEventConsumerToFilter")
| project Timestamp, DeviceName, ActionType, AdditionalFields
```
```kql
// Startup folder and LNK persistence
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has @"\Start Menu\Programs\Startup"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName
```

**Q2.6 — Splunk: corroborate C2 across the estate**
```
index=proxy OR index=firewall OR index=dns earliest=-30d
  (dest_ip="203.0.113.10" OR dest_host="c2.bad-domain.com" OR query="*bad-domain.com*")
| stats count min(_time) as firstTime max(_time) as lastTime values(action) as actions
        values(dest_port) as ports by src_ip, index
| convert ctime(firstTime) ctime(lastTime)
| sort firstTime
```

**Q2.7 — LSASS access (credential dumping)**
```kql
DeviceEvents
| where Timestamp > ago(7d) and ActionType == "OpenProcessApiCall"
| where AdditionalFields has "lsass"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, AdditionalFields
```
Any hit here that isn't your EDR or a known monitoring agent → **P1, treat as domain credential compromise.**

---

## Step 4 — Containment options

Order: **collect evidence → isolate → block → remediate.** Reversing this destroys your investigation.

### 4.1 Collect the investigation package FIRST
**Click path:** **Assets** → **Devices** → device → **Collect investigation package** → add comment → submit. Download from **Actions & submissions** → **Action center** → **History**.
**Script:** `scripts/defender_response.py collect --device HOST01 --comment "SIR0012345"`

The package contains autoruns, installed programs, network connections, prefetch, scheduled tasks, security event log, services, temp directories, users/groups, WdSupportLogs. It is your one shot at pre-remediation state.

### 4.2 Isolation — choose the option
| Option | Effect | When to choose |
|---|---|---|
| **Full isolation** | All network cut except Defender comms | Default for confirmed execution |
| **Selective isolation** | Blocks all but allows Outlook/Teams/Skype | Only when the user must stay reachable and you accept residual risk. **Not for confirmed C2** — the allowed channels can be abused. |
| **Restrict app execution** | Only Microsoft-signed binaries run | Useful when you can't afford full isolation on a production server but need to stop unsigned payloads |
| **No isolation** | — | Branch A only, or when isolation would cause greater harm than the malware (e.g. a medical device, a production DB primary) — document the risk acceptance and who accepted it |

**Click path:** device page → **Isolate device**
**Script:** `scripts/defender_response.py isolate --device HOST01 --type Full --comment "SIR0012345"`

> Isolating a server: check dependencies first. Isolating a domain controller, DHCP server, or DB primary can cause a bigger outage than the malware. For servers, get Infrastructure on the call and consider network-ACL containment instead so you keep management access.

### 4.3 Block the indicators
**Click path:** **Settings** → **Endpoints** → **Indicators** → **File hashes** / **IP addresses and URLs**
Action options: `Allowed` · `Audit` · `Block execution` · `Block and remediate` · `Warn`
Use **Block and remediate** for confirmed malware, generate alert = Yes.
**Script:** `scripts/defender_response.py indicator --value <sha256> --type FileSha256 --action BlockAndRemediate --title "SIR0012345 malware"`

### 4.4 Remediate the file
**Click path:** file page → **Stop and quarantine file** (fleet-wide)
**Script:** `scripts/defender_response.py quarantine --device HOST01 --sha1 <sha1> --comment "..."`
> The API takes **SHA1**, not SHA256. Get both hashes during triage.

### 4.5 Credential rotation decision
| Malware class | Rotate |
|---|---|
| Adware / PUP / miner | Nothing |
| Generic trojan/dropper, no cred access observed | Logged-on user password (precautionary) |
| **Infostealer** | Logged-on user + every credential saved in their browsers + any SaaS they were signed into. Treat browser vaults as fully compromised. |
| **Credential dumper / LSASS access** | Logged-on user, all cached domain accounts on the host, local admin, any service account running on the host, and any account that logged into the host in the preceding 30 days (Q8.2 in PB-08) |
| Loader / ransomware precursor | As per credential dumper, plus assume lateral movement and run PB-08 |

---

## Step 5 — Eradication and the reimage decision

**Reimage rather than clean if any of these are true:**
- Kernel-mode component, bootkit, or unsigned driver load observed
- You cannot enumerate every artifact the malware created
- Multiple persistence mechanisms found (indicates a capable operator, not commodity malware)
- Credential dumping occurred
- Loader/ransomware-precursor family
- The host is a server, or holds regulated data
- Anti-forensic behaviour observed (log clearing, timestomping, EDR tampering)

Check EDR tampering explicitly:
```kql
DeviceEvents
| where Timestamp > ago(7d) and DeviceName =~ "HOST01"
| where ActionType has_any ("TamperingAttempt","AntivirusDisabled","AntivirusScanCancelled",
        "ExploitGuardOff","SmartScreenOff","SecurityLogCleared")
| project Timestamp, DeviceName, ActionType, AdditionalFields, InitiatingProcessCommandLine
```
Cleaning a host that had EDR tampered with is not defensible. Reimage.

**If cleaning:** remove the file, remove every persistence artifact found in Q2.5, full AV scan, reboot, re-scan, then 7 days of enhanced monitoring:
```
index=proxy OR index=firewall src_ip="<host IP>" earliest=-7d
| stats count sum(bytes_out) as bytes_out by dest_ip, dest_host, dest_port
| sort - count
```

**Release from isolation** only when: clean scan, no C2 for 24h, persistence removed, credentials rotated.
**Script:** `scripts/defender_response.py unisolate --device HOST01 --comment "SIR0012345 remediation verified"`

---

## Step 6 — Verification checklist
- [ ] Investigation package collected and attached to the SIR
- [ ] Execution status determined and recorded (prevented vs executed)
- [ ] Delivery vector identified — if unknown, say so explicitly in close notes; don't imply you found it
- [ ] Hash swept fleet-wide (Q2.3), all affected hosts listed
- [ ] C2 identified and blocked at endpoint + network + DNS
- [ ] Persistence swept (all four queries in Q2.5)
- [ ] Credential rotation completed per the table in 4.5
- [ ] Reimage-or-clean decision documented with reasoning
- [ ] Detection created for the IoCs
- [ ] Host released from isolation and monitored 7 days

## Step 7 — False positives
| Pattern | Confirm | Action |
|---|---|---|
| Pentest / red team tooling | Engagement register | Deconflict; contain anyway if uncertain |
| Admin tooling (PsExec, nircmd, procdump) | Named admin + ticket | Add to `rmm_tools.csv` as approved if genuinely sanctioned |
| Packed or novel installer | Vendor signature, publisher | Submit to Microsoft; allowlist by cert not hash |
| Miner FP on legitimate HPC/render workload | Owner confirmation | Allowlist the specific binary path |
| Dev builds triggering AV | Build server, unsigned output | Path exclusion scoped narrowly; never exclude a whole drive |

## Step 8 — ServiceNow
Category `Malware` · Subcategory `Trojan / Infostealer / Loader / Miner / PUP / Credential Dumper`
Affected CI = every host from Q2.3. Attach: investigation package, process tree screenshot, hash sweep CSV.
Close notes must state: execution status, delivery vector, malware family, scope, credential rotation performed, reimage decision.

---
---

# PB-03 · Ransomware

**Default priority: P1. Always. No triage step comes before containment.**

> **Containment beats evidence in this playbook only.** Every other runbook says collect first. Here, minutes of encryption equal permanent data loss. Isolate first, collect after.

---

## Step 1 — First 15 minutes (do these in parallel, not sequentially)

| # | Action | How | Owner |
|---|---|---|---|
| 1 | **Isolate every affected device** | Defender incident page → select all devices → Isolate. Or `scripts/defender_response.py isolate-bulk --file hosts.txt` | L2 |
| 2 | **Do NOT power off** | Powering off destroys memory, which may hold keys. Network isolation only. | all |
| 3 | **Protect backups** | Verify immutability/air-gap. If in doubt, disconnect the backup network. Attackers target backups before encrypting. | Infrastructure |
| 4 | **Disable compromised accounts** | `scripts/Invoke-IdentityContainment.ps1 -UserPrincipalName x -RevokeSessions -BlockSignIn` | Identity |
| 5 | **Open the bridge** | SOC Lead, CISO, Infra, Legal, Comms, Backup owner | SOC Lead |
| 6 | **Start the log** | One person owns a running timeline in the SIR. Not optional at P1. | Scribe |
| 7 | **Assume it's still spreading** | Until proven otherwise | all |

**Do NOT do these in the first hour:** email the whole company, talk to the attacker, delete anything, restore from backup (you'll re-encrypt), or let anyone reimage a host before it's been imaged for evidence.

---

## Step 2 — Scoping queries

**Q3.1 — Recovery destruction (usually the earliest reliable signal)**
```kql
DeviceProcessEvents
| where Timestamp > ago(3d)
| where FileName in~ ("vssadmin.exe","wmic.exe","bcdedit.exe","wbadmin.exe","diskshadow.exe","cipher.exe","powershell.exe")
| where ProcessCommandLine has_any ("delete shadows","shadowcopy delete","resize shadowstorage",
        "recoveryenabled no","bootstatuspolicy ignoreallfailures","delete catalog",
        "Win32_ShadowCopy","delete systemstatebackup","/w:")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```
The **earliest** row here is close to your encryption start time. Work backwards from it to find initial access.

**Q3.2 — Encryption in progress / extent**
```kql
DeviceFileEvents
| where Timestamp > ago(2d)
| where ActionType in ("FileRenamed","FileModified","FileCreated")
| extend ext = tostring(split(FileName, ".")[-1])
| summarize Files=count(), Exts=make_set(ext, 15), Procs=make_set(InitiatingProcessFileName, 5)
    by DeviceName, bin(Timestamp, 5m)
| where Files > 300
| order by Timestamp asc
```
A single new extension appearing across thousands of files is the ransom extension. Note it — it identifies the family.

**Q3.3 — Ransom note discovery (gives you the family and the leak-site)**
```kql
DeviceFileEvents
| where Timestamp > ago(2d) and ActionType == "FileCreated"
| where FileName matches regex @"(?i)(readme|how[_ -]?to[_ -]?(decrypt|restore)|recover|restore[_-]?files|decrypt|unlock|ransom|!!!)"
| where FileName endswith ".txt" or FileName endswith ".hta" or FileName endswith ".html" or FileName endswith ".README"
| summarize Hosts=dcount(DeviceName), Sample=any(FolderPath) by FileName
| order by Hosts desc
```

**Q3.4 — File share blast radius (Splunk)**
```
index=wineventlog (EventCode=5145 OR EventCode=4663) earliest=-2d
| stats dc(Object_Name) as objects_touched values(Accesses) as access_types
        min(_time) as firstTime max(_time) as lastTime
        by Account_Name, Source_Address, host
| where objects_touched > 500
| convert ctime(firstTime) ctime(lastTime)
| sort - objects_touched
```

**Q3.5 — The account doing the encrypting, and everywhere it has been**
```kql
DeviceLogonEvents
| where Timestamp > ago(14d) and AccountName =~ "<encrypting account>"
| summarize Hosts=make_set(DeviceName, 100), HostCount=dcount(DeviceName),
            FirstSeen=min(Timestamp) by AccountName, LogonType
| order by HostCount desc
```
Every host in that list is potentially staged even if not yet encrypted. Isolate them too.

**Q3.6 — Find initial access (you must answer this or it recurs)**
Work through these in order — one of them is almost always the answer:
```
# 1. Exposed RDP or VPN with no MFA
index=firewall dest_port IN (3389, 443) action=allowed earliest=-30d
    NOT src_ip IN (<corporate ranges>)
| stats count dc(dest_ip) as targets by src_ip, dest_port | where count > 20
```
```
# 2. VPN authentication from anomalous source
index=vpn action=success earliest=-30d
| stats count values(src_ip) as ips values(location) as geo by user
| where mvcount(ips) > 3
```
```kql
// 3. Phishing → loader (check 14-30 days back, not 2)
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("outlook.exe","winword.exe","excel.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","mshta.exe","wscript.exe","msiexec.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```
```kql
// 4. Edge device / web exploitation
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("w3wp.exe","java.exe","nginx.exe","httpd.exe","tomcat9.exe")
| where FileName in~ ("cmd.exe","powershell.exe","bash","sh","whoami.exe")
```
```kql
// 5. Unauthorized RMM installed as the access channel
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("anydesk.exe","screenconnect.clientservice.exe","atera.exe","splashtop.exe","rustdesk.exe","logmein.exe","ngrok.exe")
| summarize FirstSeen=min(Timestamp), Hosts=make_set(DeviceName,20) by FileName
```
**Dwell time is usually 3–30 days.** If you only look at the last 48 hours you will find the encryption and miss the intrusion.

**Q3.7 — Was data stolen before encryption? (double extortion — assume yes)**
```
index=proxy OR index=firewall earliest=-30d
| stats sum(bytes_out) as bytes_out by src_ip, dest_ip, dest_host
| eval GB=round(bytes_out/1024/1024/1024,2)
| where GB > 5
| sort - GB
```
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("rclone.exe","megasync.exe","winscp.exe","filezilla.exe","7z.exe","winrar.exe","rar.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```
`rclone` with a remote config, or mass archive creation before the encryption timestamp, means exfiltration occurred. **This changes it from an availability incident to a data breach with notification obligations.** Escalate to Legal immediately with what you have.

---

## Step 3 — Decision tree

```
Ransomware confirmed
│
├─ Is encryption still active?
│   ├─ YES → Isolate everything now. Skip all analysis. Come back to it.
│   └─ NO  → Isolate anyway, then proceed to scoping.
│
├─ Are Domain Controllers / tier-0 affected?
│   ├─ YES → FULL DOMAIN COMPROMISE. Plan AD recovery, not host recovery.
│   │        Engage external IR retainer. KRBTGT double-reset will be required
│   │        (manual, planned, two stages with the required interval — do NOT script this).
│   └─ NO  → Host-level recovery may be viable.
│
├─ Are backups intact and verified restorable?
│   ├─ YES → Recovery path: rebuild + restore. Test-restore one system first.
│   ├─ PARTIAL → Prioritize by business criticality with the business, not by SOC guess.
│   └─ NO  → Escalate to exec immediately. This is now a business continuity event,
│            not a security incident. Payment discussion is Legal/Exec only — SOC
│            documents facts and does not advise on payment.
│
├─ Was data exfiltrated? (Q3.7)
│   ├─ YES / UNKNOWN → Treat as a data breach. Legal owns notification clocks.
│   │                  Preserve the exfil evidence separately.
│   └─ NO (proven)   → Availability incident only. Say "no evidence of exfiltration",
│                      not "no exfiltration occurred" — those are different claims.
│
└─ Is initial access identified? (Q3.6)
    ├─ YES → Close the vector BEFORE recovery, or you will be re-encrypted mid-restore.
    └─ NO  → Do not begin recovery. Keep hunting. Recovering into an
             un-remediated environment is the most common cause of a second event.
```

---

## Step 4 — Eradication and recovery

**Sequence — do not reorder:**
1. Close the initial access vector (patch, disable, MFA, firewall).
2. Reset all privileged credentials. If AD compromised: KRBTGT twice (manual, planned), all Domain Admins, all service accounts, DSRM, Azure AD Connect account, backup service accounts.
3. Rebuild DCs / tier-0 from known-good media. Never clean a compromised DC.
4. Rebuild affected hosts from images. Do not decrypt-in-place on an un-rebuilt host.
5. Restore data from verified-clean backups. **Scan restored data before reconnecting** — backups may contain the loader.
6. Stage the reconnection: DC/identity → core infra → business-critical apps → general fleet. Monitor between each stage.
7. Keep enhanced monitoring for 30 days minimum. Re-intrusion attempts are common.

**Deploy a canary before declaring recovery:** put a file-share honeypot with a mass-modification alert on it. If it fires, you're not clean.

## Step 5 — Verification
- [ ] Initial access vector identified and closed (or explicitly documented as unknown, with exec sign-off to proceed)
- [ ] All tier-0 credentials rotated; KRBTGT double-reset completed if AD compromised
- [ ] Every host from Q3.5 accounted for — encrypted, staged-but-clean, or unaffected
- [ ] Exfiltration assessed (Q3.7) and Legal briefed with findings
- [ ] Backups verified clean before restore, and restored data scanned
- [ ] Canary/honeypot deployed
- [ ] 30-day enhanced monitoring in place
- [ ] Post Incident Review scheduled (mandatory)

## Step 6 — ServiceNow
P1 SIR, link to Major Incident. Category `Ransomware`.
Parallel task list: Comms, Legal/regulatory clock, Insurance notification, Law enforcement (per policy), Customer/partner notification, Backup restore tracking, Per-host rebuild tracking.
Track regulatory clocks explicitly as tasks with due dates — Legal owns the determination, but the SIR is where the clock is visible.

---
---

# PB-07 · LOLBin / Suspicious Scripting

**Default priority:** P2 · P3 if it resolves to known admin automation

**What this catches:** encoded PowerShell, script hosts abusing signed binaries, fileless execution. What it does *not* tell you is intent — that's your job.

## Step 1 — Decode before you decide
This is the whole runbook in one step. Do not escalate or close an encoded-command alert without decoding it.

```powershell
# scripts/Decode-EncodedCommand.ps1  (safe: decodes only, does not execute)
$b64 = '<base64 string from the -enc argument>'
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($b64))
```
```bash
# Linux/Mac equivalent
echo '<base64>' | base64 -d | iconv -f UTF-16LE -t UTF-8
```
Handle gzip/deflate-wrapped payloads (common second layer):
```powershell
$bytes = [System.Convert]::FromBase64String('<inner base64>')
$ms = New-Object IO.MemoryStream(,$bytes)
$ds = New-Object IO.Compression.DeflateStream($ms,[IO.Compression.CompressionMode]::Decompress)
(New-Object IO.StreamReader($ds)).ReadToEnd()
```
> Decode in an isolated analysis VM or a container. Do not run the decoded content. Reading is safe; executing is not.

## Step 2 — Decision tree
```
Suspicious script execution
│
├─ Decoded successfully?
│   ├─ NO (multi-layer, unreadable) → treat as malicious. P2. Isolate. PB-02.
│   └─ YES → read it
│       │
│       ├─ Downloads and executes remote content  → malicious. PB-02, P2.
│       ├─ In-memory injection (VirtualAlloc,
│       │  reflection, Add-Type, DllImport)       → malicious, capable operator. P1.
│       ├─ Credential access (LSASS, DPAPI,
│       │  SAM, browser vaults, Get-Credential
│       │  harvesting)                            → P1. PB-02 credential-dumper path + PB-08.
│       ├─ Recon (Get-ADUser, Get-ADComputer,
│       │  nltest, net group, ADRecon, SharpHound
│       │  patterns)                              → P2. Attacker mapping the domain.
│       │                                            Expect lateral movement next → PB-08.
│       ├─ Defence evasion (AMSI bypass, ETW
│       │  patching, Set-MpPreference exclusions,
│       │  clearing logs)                         → P1. Deliberate, skilled. Reimage the host.
│       ├─ Legitimate admin task                 → verify with the named admin AND a ticket.
│       │                                            Verbal-only confirmation is not enough
│       │                                            when the account may be compromised —
│       │                                            confirm out-of-band.
│       └─ Ambiguous                              → escalate to L2. Do not close ambiguous.
│
└─ Parent process check (overrides the above)
    ├─ Office app / script host parent → phishing payload, PB-01 Branch D
    ├─ Web server parent               → PB-11, P1
    └─ services.exe / WMI parent       → persistence or remote exec, widen the window
```

## Step 3 — Queries

**Q7.1 — Scored suspicious PowerShell** (also shipped as a correlation search)
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe","pwsh.exe","powershell_ise.exe")
| extend cmd = tolower(ProcessCommandLine)
| extend score =
      (iff(cmd matches regex @"\s-e(nc|ncodedcommand|c)?\s", 3, 0))
    + (iff(cmd has "frombase64string", 3, 0))
    + (iff(cmd has_any ("downloadstring","downloadfile","invoke-webrequest","invoke-restmethod","net.webclient","start-bitstransfer"), 2, 0))
    + (iff(cmd has_any ("-w hidden","-windowstyle hidden","-nop","-noprofile","-noni"), 1, 0))
    + (iff(cmd has_any ("bypass","unrestricted"), 1, 0))
    + (iff(cmd has_any ("iex","invoke-expression"), 2, 0))
    + (iff(cmd has_any ("reflection.assembly","virtualalloc","createthread","memorystream","deflatestream","add-type"), 3, 0))
    + (iff(cmd has_any ("lsass","sekurlsa","minidump","comsvcs.dll"), 4, 0))
    + (iff(InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","mshta.exe","wscript.exe","cscript.exe"), 3, 0))
| where score >= 5
| project Timestamp, DeviceName, AccountName, score, InitiatingProcessFileName, ProcessCommandLine
| order by score desc, Timestamp desc
```

**Q7.2 — LOLBin abuse patterns**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName =~ "certutil.exe"   and ProcessCommandLine has_any ("-urlcache","-decode","-encode","-f http"))
     or (FileName =~ "bitsadmin.exe"  and ProcessCommandLine has_any ("/transfer","/addfile"))
     or (FileName =~ "regsvr32.exe"   and ProcessCommandLine has_any ("scrobj.dll","/i:http","/i:ftp"))
     or (FileName =~ "mshta.exe"      and ProcessCommandLine has_any ("http","javascript:","vbscript:"))
     or (FileName =~ "rundll32.exe"   and ProcessCommandLine has_any ("javascript:","url.dll","OpenURL","shell32.dll,Control_RunDLL"))
     or (FileName =~ "msbuild.exe"    and ProcessCommandLine has_any (".csproj",".xml","/p:"))
     or (FileName =~ "installutil.exe" and ProcessCommandLine has "/logfile=")
     or (FileName =~ "wmic.exe"       and ProcessCommandLine has_any ("process call create","/node:","os get"))
     or (FileName =~ "msiexec.exe"    and ProcessCommandLine has_any ("http://","https://"))
     or (FileName =~ "curl.exe"       and ProcessCommandLine has_any ("-o ","--output"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

**Q7.3 — Defence evasion**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("Set-MpPreference","Add-MpPreference","-DisableRealtimeMonitoring",
        "-ExclusionPath","-ExclusionProcess","amsiInitFailed","AmsiUtils","wevtutil cl",
        "Clear-EventLog","fsutil usn deletejournal","sc stop WinDefend","sc config WinDefend")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```
Any hit → **P1, reimage.** Someone is deliberately blinding your tooling.

**Q7.4 — Splunk: PowerShell script block logging (richer than command line)**
```
index=wineventlog sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| eval sb=lower(ScriptBlockText)
| search sb IN ("*frombase64string*","*downloadstring*","*virtualalloc*","*lsass*","*amsi*","*-enc *","*reflection.assembly*")
| table _time, host, UserID, ScriptBlockText
```
> If EventCode 4104 isn't in Splunk, enabling PowerShell script block logging via GPO is one of the highest-value, lowest-cost detection improvements available. Raise it as a Change.

## Step 4 — Containment
Same as PB-02 (§4). Additionally: if defence-evasion or credential-access content was found, skip the clean/reimage debate and reimage.

## Step 5 — FPs and tuning
| Source | Fix |
|---|---|
| SCCM / Intune / Nexthink scripts | Exclude by **signed script path + expected parent process**, never by process name alone |
| Software deployment | Baseline your deployment window and exclude within it |
| Monitoring agents using encoded commands | Allowlist the specific full command-line hash |
| Developers running build scripts | Scope exclusion to dev subnets and named users |

**Never exclude `powershell.exe` broadly.** That removes visibility of the most-used attack tool in the environment. Every exclusion needs an owner, a justification, and a review date recorded in a lookup.

---
---

# PB-15 · Unauthorized RMM / Remote Access Tooling

**Default priority: P2, not P4.** The playbook index rates shadow IT as P4; unexplained RMM software is different. It's the standard initial-access-broker and ransomware-affiliate persistence channel. Treat it as suspected intrusion until a named human explains it.

## Step 1 — Decision tree
```
RMM / tunnelling tool detected
│
├─ Is it in rmm_tools.csv as approved=true?
│   ├─ YES → verify version and expected host scope. If it's on a host outside the
│   │        approved scope, that is still suspicious. Otherwise close P4.
│   └─ NO  → continue
│
├─ Can a NAMED person, contacted OUT-OF-BAND, explain why it's there?
│   │  (out-of-band matters — if the account is compromised, an email/Teams "yes that
│   │   was me" may be the attacker)
│   ├─ YES, with a business reason
│   │   → policy violation, not incident. Remove, offer the sanctioned alternative,
│   │     note to HR per AUP. Close P4. Add to the approved lookup only if the
│   │     business genuinely approves it.
│   └─ NO / cannot reach them / explanation doesn't hold
│       → SUSPECTED INTRUSION. P2. Continue below.
│
├─ How did it get installed? (Q15.2)
│   ├─ User double-clicked an installer from a download/email  → PB-01, likely social
│   │   engineering ("fake IT support", "vishing", fake update)
│   ├─ Pushed remotely (WMI/PsExec/GPO/SCCM without a change)  → PB-08, P1
│   ├─ Silent install with /S or msiexec /qn                   → automated, scripted attack
│   └─ Installed by SYSTEM with no user session                → already-compromised host
│
├─ Is it phoning home / is there an active session? (Q15.3)
│   ├─ YES, active session → P1. Someone is connected right now. Isolate immediately.
│   └─ NO                 → P2, isolate, investigate
│
└─ Is it on more than one host? (Q15.1)
    └─ 2+ → treat as a deployed persistence channel. P1. Run PB-08.
```

## Step 2 — Queries

**Q15.1 — Fleet sweep for RMM and tunnelling tools**
```kql
let rmm = dynamic(["anydesk.exe","teamviewer.exe","tvnserver.exe","screenconnect.clientservice.exe",
  "connectwisecontrol.client.exe","atera.exe","syncro.exe","splashtop.exe","srmanager.exe",
  "rustdesk.exe","ngrok.exe","cloudflared.exe","localtonet.exe","gotohttp.exe","remoteutilities.exe",
  "supremo.exe","ammyy.exe","aa_v3.exe","dwagent.exe","meshagent.exe","logmein.exe","lmiguardiansvc.exe",
  "chrome_remote_desktop.exe","dameware.exe","radmin.exe","pcvisit.exe","zoho_assist.exe","fixme.it.exe"]);
union
 (DeviceProcessEvents | where Timestamp > ago(30d) | where FileName in~ (rmm)
    | project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, Src="Process"),
 (DeviceFileEvents    | where Timestamp > ago(30d) | where FileName in~ (rmm)
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath,
              ProcessCommandLine=InitiatingProcessCommandLine, Src="FileWrite")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Events=count(),
            Paths=make_set(FolderPath,3), Accounts=make_set(AccountName,5) by DeviceName, FileName
| order by FirstSeen asc
```

**Q15.2 — How was it installed**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d) and DeviceName =~ "HOST01"
| where ProcessCommandLine has_any ("anydesk","screenconnect","atera","splashtop","rustdesk","ngrok","meshagent")
     or FileName in~ ("msiexec.exe","anydesk.exe")
| project Timestamp, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp asc
```
Read `InitiatingProcessAccountName`: `SYSTEM` with no interactive session → pushed, not user-installed. `explorer.exe` parent → user double-clicked it (social engineering). `wmiprvse.exe` / `psexesvc.exe` parent → remote push, run PB-08.

**Q15.3 — Active session / phone-home**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("anydesk.exe","screenconnect.clientservice.exe","rustdesk.exe","ngrok.exe","cloudflared.exe","meshagent.exe","atera.exe")
| summarize Connections=count(), Bytes=sum(todouble(coalesce(tolong(1),tolong(1)))),
            FirstSeen=min(Timestamp), LastSeen=max(Timestamp),
            Remotes=make_set(strcat(RemoteIP,":",tostring(RemotePort)), 10)
    by DeviceName, InitiatingProcessFileName
| order by LastSeen desc
```
```
index=firewall OR index=proxy earliest=-7d src_ip="<host>"
    (dest_host="*anydesk*" OR dest_host="*teamviewer*" OR dest_host="*screenconnect*"
     OR dest_host="*ngrok*" OR dest_host="*trycloudflare*" OR dest_host="*rustdesk*")
| stats count sum(bytes_in) as bytes_in sum(bytes_out) as bytes_out
        min(_time) as firstTime max(_time) as lastTime by src_ip, dest_host, dest_port
| convert ctime(firstTime) ctime(lastTime)
```
**Sustained bidirectional traffic with meaningful bytes in both directions = an active interactive session.** That is a human on the box. P1.

**Q15.4 — AnyDesk / ScreenConnect artifacts (local evidence via Live Response)**
```
# AnyDesk connection log — shows incoming connection IDs and timestamps
getfile "C:\ProgramData\AnyDesk\connection_trace.txt"
getfile "C:\ProgramData\AnyDesk\ad.trace"
getfile "C:\Users\<user>\AppData\Roaming\AnyDesk\connection_trace.txt"

# ScreenConnect
getfile "C:\Program Files (x86)\ScreenConnect Client*\app.config"
```
`connection_trace.txt` gives you the incoming AnyDesk ID — that's attributable evidence for Legal/law enforcement. Collect it before remediating.

## Step 3 — Containment options
| Option | When |
|---|---|
| **Isolate host** | Active session, or install method indicates intrusion. Default for P2+. |
| **Block the RMM domains at proxy/DNS** | Always — stops the channel across the whole estate, not just this host |
| **Add binary hash to Defender Indicators (Block execution)** | Always for unapproved tools |
| **WDAC / AppLocker deny rule** | Durable fix; raise as a Change |
| **Uninstall only** | Only for confirmed-benign policy violations |

**Click paths:** Indicators → **Settings** → **Endpoints** → **Indicators** → File hashes.
Network block: proxy/DNS categories for "Remote Access" — most proxies have this category; enabling it wholesale (with an allowlist for your sanctioned tool) is the strongest single control here.

## Step 4 — Verification
- [ ] Install method determined (user-initiated vs pushed)
- [ ] Connection logs collected as evidence before removal
- [ ] Remote peer IDs/IPs recorded and blocked
- [ ] Fleet swept (Q15.1) — all instances found, not just the alerting host
- [ ] Tool removed; hash and domains blocked; app-control rule raised
- [ ] If intrusion: credentials rotated, PB-08 lateral movement hunt completed
- [ ] `rmm_tools.csv` updated (approved or explicitly denied)

## Step 5 — FPs
Genuine IT use of TeamViewer/AnyDesk is common and legitimate. The fix is not to stop alerting — it's to maintain `rmm_tools.csv` with the approved tool, approved version, and approved host scope, so that anything outside that scope still alerts. An approved tool on an unexpected host is still worth a look.

## Step 6 — ServiceNow
Category `Unauthorized Software` if benign · `Intrusion` / `Suspicious Activity` if not. Never close as "shadow IT" without recording the named person who explained it and how you contacted them.
