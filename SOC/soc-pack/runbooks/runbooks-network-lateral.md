# NETWORK & LATERAL MOVEMENT RUNBOOKS
### PB-06 Command & Control · PB-08 Lateral Movement · PB-13 Denial of Service

---
---

# PB-06 · Command & Control / Beaconing / Suspicious Outbound

**Default priority:** P2 · **P1** if on a server, on 2+ hosts, or if the beaconing process is a signed system binary (indicates a capable operator using process injection)

**Detection sources:** Splunk correlation (`Periodic Beacon Like Outbound Connection`, `DNS Tunneling Indicators`), MDE network alerts, threat-intel IoC match, firewall/proxy anomaly.

---

## Step 1 — Identify the process. Everything depends on this.

A network alert tells you *that* something is talking out. It does not tell you *what*. Until you know the initiating process, you cannot triage.

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP == "203.0.113.10" or RemoteUrl has "c2.bad-domain.com"
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, RemotePort, Protocol,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256,
          InitiatingProcessCommandLine, InitiatingProcessAccountName,
          InitiatingProcessParentFileName
| order by Timestamp asc
```

**Interpretation table — this is the branch point:**

| Initiating process | Meaning | Priority | Next |
|---|---|---|---|
| Unknown/unsigned binary in a user-writable path (`%APPDATA%`, `%TEMP%`, `%PUBLIC%`, `C:\Users\...\Downloads`) | Straightforward malware | P2 | PB-02 |
| **Signed Microsoft binary** (`rundll32`, `regsvr32`, `svchost`, `explorer`, `dllhost`, `werfault`, `msbuild`) | Process injection or LOLBin C2. Capable operator. | **P1** | PB-07 + PB-02, plan to reimage |
| Browser (`chrome`, `msedge`, `firefox`) | Often benign — but check for malicious extension or a browser-based C2 | P3, verify | Check extensions |
| Legitimate app with an unexpected destination (e.g. Notepad++ talking to a VPS) | DLL sideloading | P1 | PB-02, reimage |
| Your own EDR/monitoring/update agent | Almost certainly FP | P4 | Add to `beacon_allowlist.csv` |
| `powershell.exe` / `python.exe` / `cscript.exe` | Script-based C2 | P2 | PB-07, decode the script |
| No process attributed (network-only telemetry) | Non-Windows device, IoT, unmanaged host, or a device without MDE | P2 | Identify the asset from DHCP/CMDB — an unmanaged device beaconing is a visibility gap as well as an incident |

> **Signed-binary C2 is the finding that most often gets under-rated.** `rundll32.exe` connecting to a VPS on 443 looks tidy in a log and is one of the more serious things you can find. Treat it as injection until proven otherwise.

---

## Step 2 — Decision tree

```
Suspicious outbound traffic
│
├─ Is the destination in beacon_allowlist.csv?
│   └─ YES → verify the process matches the expected one for that destination.
│            (An allowlisted update domain being contacted by a non-update process
│            is the attacker using a trusted destination — check this, don't just close.)
│
├─ Process identified? (Step 1)
│   ├─ NO  → identify the asset first. Unmanaged device = get MDE onto it or
│   │        contain at the network layer.
│   └─ YES → use the interpretation table above.
│
├─ Traffic pattern classification (Q6.1–Q6.4)
│   ├─ Low-jitter periodic, small payloads       → classic beacon. Sleep interval
│   │                                                = avg_interval. Note it; it helps
│   │                                                identify the framework.
│   ├─ Long-poll / held-open connections         → interactive C2 or a tunnel
│   ├─ High-volume outbound, low inbound         → EXFILTRATION, not C2 → PB-10
│   ├─ DNS-only, high unique subdomain count     → DNS tunnelling (Q6.3)
│   ├─ Traffic to a legitimate cloud/SaaS domain
│   │  (Slack, Discord, Telegram, Pastebin,
│   │  GitHub, Google Drive, Dropbox, Trello,
│   │  Notion webhooks)                          → LIVING-OFF-TRUSTED-SITES C2.
│   │                                                Domain reputation won't help you here.
│   │                                                Focus on the process, not the destination.
│   │                                                Cannot block the domain wholesale in most
│   │                                                orgs → containment must be host-level.
│   └─ Traffic over a non-standard port to a
│      raw IP with no DNS lookup                 → hardcoded C2, malware config.
│                                                   Retrieve the config if you can.
│
├─ Scope: how many hosts talk to this destination? (Q6.5)
│   ├─ 1     → P2, single-host compromise
│   ├─ 2-3   → P2/P1, campaign
│   └─ 4+    → P1. Either a shared delivery vector or automated spread. Find the vector
│              before chasing individual hosts.
│
├─ Is the traffic ALLOWED or BLOCKED at the perimeter?
│   ├─ Blocked → good, but the host is still compromised. Blocked C2 means the
│   │            implant is running and will retry or fail over. Still isolate.
│   └─ Allowed → active C2 channel. Isolate now.
│
└─ Duration: how long has this been happening? (Q6.5 firstTime)
    ├─ Hours  → early detection, good
    └─ Weeks/months → assume the attacker achieved their objectives. Expand scope
                       substantially: credential theft, lateral movement, exfiltration.
                       Long dwell changes this from "clean a host" to "assess a breach."
```

---

## Step 3 — Queries

**Q6.1 — Beacon detection by jitter (Splunk)**
```
| tstats summariesonly=true allow_old_summaries=true
    values(All_Traffic.dest_port) as dest_port sum(All_Traffic.bytes_out) as bytes_out
    sum(All_Traffic.bytes_in) as bytes_in count
    from datamodel=Network_Traffic
    where All_Traffic.action="allowed"
      NOT All_Traffic.dest IN (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8)
    by _time span=1s All_Traffic.src All_Traffic.dest
| rename "All_Traffic.*" as "*"
| lookup beacon_allowlist.csv dest OUTPUT description as known_good
| where isnull(known_good)
| sort 0 src dest _time
| streamstats current=f last(_time) as prev_time by src, dest
| eval delta=_time-prev_time
| where isnotnull(delta) AND delta > 10
| stats count as connections avg(delta) as avg_interval stdev(delta) as jitter
        sum(bytes_out) as total_out sum(bytes_in) as total_in
        dc(dest_port) as ports values(dest_port) as dest_port
        min(_time) as firstTime max(_time) as lastTime
        by src, dest
| where connections >= 30 AND avg_interval > 20 AND avg_interval < 7200
| eval jitter=round(jitter,1), avg_interval=round(avg_interval,1),
       ratio=round(jitter/avg_interval,3),
       out_in_ratio=round(total_out/(total_in+1),2)
| where ratio < 0.15
| convert ctime(firstTime) ctime(lastTime)
| sort ratio
| table firstTime, lastTime, src, dest, dest_port, connections, avg_interval, jitter, ratio, total_out, total_in, out_in_ratio
```
`ratio` is jitter divided by interval. Human and application traffic is bursty (ratio > 0.5). Beacons are regular (ratio < 0.15). Some frameworks add deliberate jitter — a 30–40% jitter setting will evade this, so also run Q6.2.

**Q6.2 — Rare-destination / newly-seen-domain detection (catches jittered beacons)**
```
index=proxy earliest=-14d
| stats dc(src_ip) as client_count count as requests
        sum(bytes_out) as bytes_out sum(bytes_in) as bytes_in
        min(_time) as firstTime max(_time) as lastTime
        values(user) as users values(http_user_agent) as agents
        by dest_host
| where client_count <= 3 AND requests > 20
| eval age_days=round((now()-firstTime)/86400,1),
       out_in_ratio=round(bytes_out/(bytes_in+1),2)
| where age_days < 7
| convert ctime(firstTime) ctime(lastTime)
| sort age_days
```
Few clients + many requests + first seen recently = the signature of a new C2 domain. Combine with a low `out_in_ratio` for C2 and a high one for exfiltration.

Also check user agent anomalies:
```
index=proxy earliest=-7d
| stats dc(dest_host) as hosts count by http_user_agent
| where hosts < 5
| sort count
```
Bespoke or malformed user agents used by only one destination are worth a look. Empty user agents on HTTP POST especially.

**Q6.3 — DNS tunnelling**
```
| tstats summariesonly=true allow_old_summaries=true count
    from datamodel=Network_Resolution where DNS.message_type="QUERY"
    by DNS.src DNS.query
| rename "DNS.*" as "*"
| eval qlen=len(query)
| rex field=query "(?<parent>[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}$)"
| eval sub=replace(query,"\.".parent."$","")
| eval digits=len(replace(sub,"[^0-9]","")), alpha=len(replace(sub,"[^a-zA-Z]",""))
| eval numeric_ratio=if(alpha>0,round(digits/alpha,2),9)
| stats dc(query) as unique_subdomains sum(count) as total_queries
        avg(qlen) as avg_len max(qlen) as max_len avg(numeric_ratio) as avg_numeric
        by src, parent
| lookup beacon_allowlist.csv dest as parent OUTPUT description as known_good
| where isnull(known_good)
| where unique_subdomains >= 300 AND avg_len >= 40
| eval avg_len=round(avg_len,1), avg_numeric=round(avg_numeric,2)
| sort - unique_subdomains
```
Also check TXT and NULL record volume, which is unusual outside tunnelling:
```
index=dns earliest=-24h query_type IN ("TXT","NULL","CNAME")
| stats count dc(query) as unique by src_ip, query_type
| where count > 500
```
**FPs to expect:** antivirus reputation lookups, CDN and load-balancer hostnames, telemetry SDKs, some email-security products, Spotify/Netflix CDN patterns. Allowlist by parent domain in `beacon_allowlist.csv`.

**Q6.4 — Long-lived / tunnelled sessions**
```
index=firewall earliest=-24h action=allowed
| eval duration=coalesce(duration, session_duration, 0)
| where duration > 3600
| stats count values(duration) as durations sum(bytes_out) as bytes_out sum(bytes_in) as bytes_in
        by src_ip, dest_ip, dest_port, app
| sort - bytes_out
```
Multi-hour sessions to a single external IP on a non-standard port, with meaningful traffic in both directions, is an interactive tunnel — SSH reverse tunnel, ngrok, Cloudflare tunnel, or an RMM session (→ PB-15).

**Q6.5 — Scope: everything that touched this destination**
```
index=proxy OR index=firewall OR index=dns earliest=-90d
  (dest_ip="203.0.113.10" OR dest_host="c2.bad-domain.com" OR query="*bad-domain.com*")
| stats count min(_time) as firstTime max(_time) as lastTime
        values(action) as actions values(dest_port) as ports
        by src_ip, index
| convert ctime(firstTime) ctime(lastTime)
| sort firstTime
```
**Look at the 90-day window deliberately.** The oldest `firstTime` is your best estimate of intrusion start, which is usually much earlier than the alert.

**Q6.6 — Infrastructure pivot (find related C2 you haven't detected yet)**
Once you have one C2 IP or domain, pivot on:
- Same IP, other domains (passive DNS) → check each in your logs
- Same TLS certificate (JA3/JA3S, cert SHA1) → hunt the cert fingerprint
- Same ASN and adjacent /24
```
index=proxy OR index=firewall earliest=-90d dest_ip="203.0.113.0/24"
| stats count dc(src_ip) as hosts values(dest_host) as domains by dest_ip
| sort - count
```
```kql
DeviceNetworkEvents
| where Timestamp > ago(90d)
| where ipv4_is_in_range(RemoteIP, "203.0.113.0/24")
| summarize Connections=count(), Hosts=dcount(DeviceName), Devices=make_set(DeviceName,20),
            Processes=make_set(InitiatingProcessFileName,10) by RemoteIP
```
Attackers reuse infrastructure. This query frequently finds hosts you didn't know were compromised.

---

## Step 4 — Containment options

| Option | Effect | Trade-off |
|---|---|---|
| **Isolate the host** | Cuts the channel and stops the operator | Default for confirmed C2. **Do this before blocking the domain** — if you block first, the operator notices and may burn the host or deploy ransomware. |
| **Block the IoC at proxy/DNS/firewall** | Estate-wide | Do it, but *after* host isolation for known-compromised hosts. Blocking alone leaves a live implant that will fail over to a backup C2. |
| **Defender Indicator (Block and remediate)** | Follows the device off-network | Always. Covers hosts that leave the corporate network. |
| **Sinkhole the domain internally** | Lets you find other infected hosts without alerting the operator | Best option when you suspect wider compromise and want visibility before acting. Needs DNS team. |
| **Do nothing yet, monitor** | Preserves your view of the operator | **Only with SOC Lead sign-off, time-boxed, and only when you're confident the host can't reach anything critical.** Legitimate in a targeted-intrusion investigation. Not a default. |
| **Network ACL instead of EDR isolation** | Keeps management access to servers | For production servers where full isolation causes an outage |

**Sequencing for a multi-host compromise:** isolate **all** identified hosts within the same short window, then block. Sequential isolation over hours gives the operator time to relocate.

## Step 5 — Verification
- [ ] Initiating process identified on every affected host (or explicitly documented as unattributable, with the reason)
- [ ] Malware sample and config retrieved where possible
- [ ] 90-day scope query run (Q6.5); earliest activity recorded as estimated intrusion start
- [ ] Infrastructure pivot completed (Q6.6) — related C2 hunted
- [ ] All hosts from the scope query triaged, not just the alerting one
- [ ] IoCs blocked at endpoint, proxy, DNS, and firewall
- [ ] Backup/failover C2 hunted (check the malware config, and look for other rare destinations from the same host)
- [ ] PB-02 eradication completed per host
- [ ] Detection created for the IoCs and for the pivot infrastructure
- [ ] Long-dwell cases: credential theft, lateral movement (PB-08) and exfiltration (PB-10) assessed

## Step 6 — False positives
| Pattern | Fix |
|---|---|
| Software update checkers (Adobe, Chrome, Java, vendor agents) | `beacon_allowlist.csv` by destination **and** expected process |
| Telemetry / analytics / crash reporting SDKs | Same |
| Monitoring and RMM agents (your sanctioned one) | Same |
| Certificate revocation (OCSP/CRL) checks | Allowlist |
| VoIP / Teams / SIP keepalives | Allowlist by port and destination |
| NTP | Allowlist |
| IoT / building management / printers phoning home | Document the asset; these are also a real risk surface |
| Someone's crypto miner (personal) | Not a beacon FP — it's PB-15 |

Maintaining `beacon_allowlist.csv` is the difference between a usable rule and a rule everyone ignores. Budget real time for it during rollout.

## Step 7 — ServiceNow
Category `Command and Control` / `Malicious Network Activity`. Affected CI = every host from Q6.5.
Close notes must include: the initiating process, the estimated intrusion start date (from the 90-day query), and whether exfiltration was assessed.

---
---

# PB-08 · Lateral Movement

**Default priority: P1.** Lateral movement means an attacker is already inside, has credentials, and is expanding. There is no P3 version of this.

**Detection sources:** Splunk correlation (`Account Authenticating To Excessive Hosts`), MDI alerts (remote code execution, suspicious replication, pass-the-ticket, pass-the-hash, overpass-the-hash), MDE alerts, discovery during PB-02/PB-04/PB-06.

---

## Step 1 — Containment principle: isolate simultaneously, not sequentially

This is the defining operational rule of this playbook. If you isolate host A, investigate for 40 minutes, then isolate host B, the attacker has moved to host C. Build the full host list first (Q8.1, Q8.2), then isolate everything at once.

```bash
# Build the list from your queries, then:
python3 scripts/defender_response.py isolate-bulk --file affected_hosts.txt \
    --type Full --comment "SIR0012345 coordinated lateral movement containment"
```

Accept that your host list will be incomplete. Isolate what you have, keep hunting, isolate again. But do not isolate one-at-a-time while investigating.

---

## Step 2 — Decision tree

```
Lateral movement suspected
│
├─ Identify the compromised credential(s) (Q8.1)
│   → Everything follows from this. The account is the attacker's tool.
│
├─ Build the full host list (Q8.1 + Q8.2 + Q8.3)
│   → Every host the account authenticated to in 30 days, plus every host it
│     authenticated FROM. Both directions.
│
├─ Is any tier-0 asset in the list?
│   │  (Domain Controller, ADFS/Entra Connect, PKI/CA, backup server,
│   │   jump box, PAM vault, hypervisor management, EDR console, SIEM)
│   ├─ YES → FULL DOMAIN COMPROMISE POSTURE.
│   │        • Assume all credentials are compromised
│   │        • Engage SOC Lead, CISO, Infrastructure, external IR retainer
│   │        • Plan AD recovery, not host cleanup
│   │        • KRBTGT double reset will be required (manual, planned)
│   │        • Do NOT use domain admin credentials to investigate — you'll
│   │          expose them to the attacker. Use local accounts and out-of-band
│   │          management.
│   └─ NO  → host-level containment may be sufficient. Verify with Q8.5.
│
├─ Technique identification (Q8.3–Q8.7) — determines what to rotate
│   ├─ Pass-the-hash (NTLM, LogonType 3)       → NTLM hashes stolen. Rotate all
│   │                                              accounts cached on the source host.
│   ├─ Pass-the-ticket / overpass-the-hash     → Kerberos tickets stolen. KRBTGT
│   │                                              consideration.
│   ├─ Remote service creation (PsExec-like)   → admin creds in use. Check event 7045.
│   ├─ WMI / WinRM remote execution            → admin creds in use.
│   ├─ RDP internal hopping                    → interactive session; check for
│   │                                              saved credentials on each hop.
│   ├─ Scheduled task creation on remote hosts → persistence + execution.
│   ├─ SMB admin share writes (ADMIN$, C$, IPC$) → payload staging. Find the payload.
│   ├─ DCOM / MMC20 / ShellWindows              → less common, more capable actor.
│   └─ SSH key reuse (Linux estate)             → rotate keys, check authorized_keys.
│
├─ Is there an attacker interactive session live right now?
│   │  (RDP session active, RMM connected, C2 with recent traffic)
│   ├─ YES → isolate immediately, do not finish your analysis first
│   └─ NO  → you have some time, but hours not days
│
└─ Objective assessment: what were they after?
    ├─ Heading toward file shares / DB servers  → data theft (PB-10)
    ├─ Heading toward backup infrastructure     → RANSOMWARE STAGING (PB-03).
    │                                               Protect backups NOW.
    ├─ Heading toward DCs                        → domain takeover
    └─ Broad, undirected                         → early-stage recon, or an
                                                    automated worm
```

---

## Step 3 — Queries

**Q8.1 — Account authenticating to abnormally many hosts**
```
| tstats summariesonly=true allow_old_summaries=true count
    min(_time) as firstTime max(_time) as lastTime
    from datamodel=Authentication
    where Authentication.action="success"
      NOT Authentication.user IN ("*$","ANONYMOUS LOGON","SYSTEM","LOCAL SERVICE","NETWORK SERVICE","-")
    by Authentication.user Authentication.src Authentication.dest
| rename "Authentication.*" as "*"
| lookup expected_admin_hosts.csv user OUTPUT justification
| where isnull(justification)
| stats dc(dest) as host_count values(dest) as hosts values(src) as sources
        sum(count) as logons min(firstTime) as firstTime max(lastTime) as lastTime
        by user
| where host_count > 10
| convert ctime(firstTime) ctime(lastTime)
| sort - host_count
```

**Q8.2 — Full host list for a compromised account, both directions (build your isolation list from this)**
```kql
let acct = "compromised_user";
let lookback = 30d;
union
 (DeviceLogonEvents | where Timestamp > ago(lookback) and AccountName =~ acct
    | project Timestamp, Host=DeviceName, Direction="destination", LogonType, RemoteIP, ActionType),
 (DeviceLogonEvents | where Timestamp > ago(lookback) and RemoteDeviceName != "" and AccountName =~ acct
    | project Timestamp, Host=RemoteDeviceName, Direction="source", LogonType, RemoteIP, ActionType)
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Logons=count(),
            Types=make_set(LogonType,5), Directions=make_set(Direction,2) by Host
| order by FirstSeen asc
```
Export this to `affected_hosts.txt` and feed it to the bulk isolation script.

**Q8.3 — Pass-the-hash indicators**
```
index=wineventlog EventCode=4624 earliest=-7d
  Logon_Type=3 Authentication_Package=NTLM
  NOT Account_Name="*$" NOT Account_Name="ANONYMOUS LOGON"
| stats dc(ComputerName) as targets values(ComputerName) as target_hosts count
        min(_time) as firstTime max(_time) as lastTime
        by Account_Name, Source_Network_Address
| where targets > 3
| convert ctime(firstTime) ctime(lastTime)
| sort - targets
```
In a Kerberos-first environment, NTLM network logons to many hosts from one source is a strong PtH signal. Note: some legacy applications legitimately use NTLM — build an exception list, don't disable the rule.

```kql
IdentityLogonEvents
| where Timestamp > ago(7d) and Protocol == "Ntlm"
| summarize Targets=dcount(DeviceName), Devices=make_set(DeviceName,20) by AccountName, IPAddress
| where Targets > 3
```

**Q8.4 — Remote execution: services, tasks, WMI**
```
index=wineventlog EventCode=7045 earliest=-7d
| table _time, ComputerName, Service_Name, Service_File_Name, Service_Type, Account_Name
| sort _time
```
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType in ("ServiceInstalled","ScheduledTaskCreated","ScheduledTaskUpdated")
| project Timestamp, DeviceName, ActionType, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine, AdditionalFields
| order by Timestamp asc
```
```kql
// WMI remote execution — wmiprvse spawning anything is worth reading
DeviceProcessEvents
| where Timestamp > ago(7d) and InitiatingProcessFileName =~ "wmiprvse.exe"
| where FileName !in~ ("conhost.exe","wermgr.exe","werfault.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```
```kql
// PsExec-family and remote-exec tooling
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","remcom.exe","csexec.exe","winrs.exe","wmic.exe")
     or ProcessCommandLine has_any ("\\\\ADMIN$","\\\\IPC$","-accepteula","/node:","Enter-PSSession","Invoke-Command -ComputerName")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

**Q8.5 — Internal RDP hopping**
```
index=wineventlog EventCode=4624 Logon_Type IN (10, 7) earliest=-7d
| stats count values(ComputerName) as targets dc(ComputerName) as target_count
        min(_time) as firstTime max(_time) as lastTime
        by Account_Name, Source_Network_Address
| where target_count > 3
| convert ctime(firstTime) ctime(lastTime)
| sort - target_count
```
```
# East-west RDP at the network layer — catches hosts without agents
index=firewall dest_port=3389 earliest=-7d
    src_ip IN (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    dest_ip IN (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
| stats count dc(dest_ip) as targets values(dest_ip) as dest_list by src_ip
| where targets > 5
| sort - targets
```

**Q8.6 — SMB payload staging**
```kql
DeviceFileEvents
| where Timestamp > ago(7d) and ActionType == "FileCreated"
| where FolderPath has_any (@"\ADMIN$", @"\C$\Windows\", @"\C$\Temp", @"\C$\PerfLogs", @"\C$\Users\Public")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessAccountName, RequestAccountName
| order by Timestamp asc
```
Hash every file found here and sweep the fleet for it (PB-02 Q2.3).

**Q8.7 — Discovery / reconnaissance (usually precedes movement — find it and you find the start)**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where (FileName =~ "net.exe" and ProcessCommandLine has_any ("group","user","view","share","localgroup","time"))
     or (FileName =~ "net1.exe")
     or FileName in~ ("nltest.exe","dsquery.exe","adfind.exe","netscan.exe","advanced_ip_scanner.exe","nbtscan.exe","sharphound.exe","azurehound.exe")
     or ProcessCommandLine has_any ("Get-ADUser","Get-ADComputer","Get-ADGroupMember","Get-DomainUser",
        "Get-NetComputer","Invoke-ShareFinder","Get-DomainController","nltest /dclist",
        "net group \"domain admins\"","Get-ADTrust","Get-NetSession")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```
The earliest row here is often close to your true intrusion start. Reconnaissance precedes movement by hours or days.

**Q8.8 — Linux estate lateral movement**
```
index=linux sourcetype=linux_secure earliest=-7d "Accepted publickey" OR "Accepted password"
| rex "for (?<user>\S+) from (?<src_ip>\S+)"
| stats dc(host) as targets values(host) as hosts count by user, src_ip
| where targets > 3
| sort - targets
```
Also check `~/.ssh/authorized_keys` modifications and new SSH keys across the estate.

---

## Step 4 — Containment options

| Option | When | Notes |
|---|---|---|
| **Bulk simultaneous host isolation** | Default | Build the list from Q8.2 first. Use the bulk script. |
| **Disable the compromised account(s)** | Always | And revoke Kerberos tickets by resetting the password twice for domain accounts |
| **Contain user in Defender XDR** | Always | Blocks the identity across MDE-managed devices |
| **Network segmentation ACL** | When you can't isolate servers | Block east-west SMB/RDP/WinRM between the affected segment and everything else |
| **Disable RDP / WinRM estate-wide temporarily** | Aggressive, effective, disruptive | For active domain compromise. Needs exec sign-off and a comms plan. |
| **Block NTLM (audit first)** | Durable fix for PtH | Long project; raise as a Change, don't attempt mid-incident |
| **Rotate local admin passwords (LAPS)** | Always if local admin was used | If you don't have LAPS, that's the top finding from this incident |

**Credential rotation scope — this is where incidents get re-opened:**
1. The compromised account(s)
2. Every account cached on **every** host in the Q8.2 list (not just the ones you isolated)
3. Local administrator on every affected host
4. Every service account running on any affected host
5. If tier-0 touched: all Domain Admins, all service accounts, DSRM, Entra Connect sync account, backup service accounts, and KRBTGT twice (manual, planned, staged)

> Rotating credentials while the attacker still has access just gives them the new ones. **Contain first, then rotate.** And do not authenticate to a compromised host with a privileged account during investigation — use local credentials or out-of-band management, or you hand over fresh material.

## Step 5 — Verification
- [ ] Full host list built (Q8.2) and every host triaged, not just isolated
- [ ] Technique identified — determines rotation scope
- [ ] Tier-0 involvement definitively assessed (yes/no with evidence)
- [ ] All isolation done in one window, not sequentially
- [ ] Credential rotation completed for all five categories above
- [ ] Persistence swept on every host (PB-02 Q2.5)
- [ ] Payload staging files found, hashed, and swept fleet-wide
- [ ] Reconnaissance timeline established (Q8.7) → true intrusion start recorded
- [ ] Attacker objective assessed (data / backups / DCs) and that path checked
- [ ] Initial access vector identified — if not, the hunt continues
- [ ] LAPS / segmentation / NTLM findings raised as Changes
- [ ] 30-day enhanced monitoring on all affected accounts and hosts

## Step 6 — ServiceNow
P1 SIR. Category `Lateral Movement` / `Intrusion`. Link every affected CI.
Task list: per-host triage, credential rotation tranches, tier-0 assessment, initial-access hunt, rotation verification.
Post Incident Review mandatory. Expect the PIR to produce segmentation and privileged-access findings — those are the durable fixes.

---
---

# PB-13 · Denial of Service / DDoS

**Default priority:** P1 if a customer-facing or revenue-generating service is degraded · P2 if internal only · P3 if mitigated automatically with no impact

## Step 1 — Confirm it's an attack, not a failure

Roughly half of suspected DDoS events are capacity problems, bad deploys, or a marketing campaign. Answer this first, because the response is entirely different.

```
index=web earliest=-2h
| timechart span=1m count as requests, dc(clientip) as unique_clients,
    avg(response_time) as avg_response
```
```
index=web earliest=-2h
| timechart span=1m count by status
```

| Observation | Likely cause |
|---|---|
| Request rate up **and** unique client count up proportionally | Genuine traffic spike or distributed attack — check client distribution |
| Request rate up, unique clients **flat or low** | Attack from few sources, or a broken retry loop in a client app |
| Request rate **normal**, response times up, 5xx up | **Not an attack.** Capacity, dependency failure, or a bad deploy. Route to Ops. |
| Traffic spike correlating with a marketing send or press mention | Legitimate. Scale, don't block. |
| Highly uniform requests (same path, same UA, same body size) | Attack |
| Traffic from one country/ASN you have no customers in | Attack |
| Started exactly on the hour | Automated tooling |

## Step 2 — Classify the layer
| Layer | Signature | Mitigation owner |
|---|---|---|
| **L3/L4 volumetric** (UDP flood, amplification, SYN flood) | Bandwidth saturated, packet counts far above baseline, upstream links hot | ISP / scrubbing provider. You cannot mitigate this on your own edge — the pipe is full. Escalate upstream immediately. |
| **L7 application** (HTTP flood, slow POST, expensive-query abuse) | Normal bandwidth, application CPU/DB saturated, high request rate | WAF, rate limiting, CDN, application caching |
| **Protocol** (SYN/ACK, fragmentation) | Connection-table exhaustion, SYN backlog | Firewall/load-balancer tuning, SYN cookies |
| **Application logic abuse** (expensive search, unauthenticated report generation) | Low request rate, high backend cost | Application fix + rate limit on the specific endpoint |

```
# L4 view
index=firewall earliest=-1h
| timechart span=1m sum(bytes) as bytes, count as packets by dest_ip
```
```
# L7 view — what's being hit
index=web earliest=-30m
| stats count avg(response_time) as avg_rt by uri_path, http_method
| sort - count
| head 20
```
```
# Source distribution — is it distributed or concentrated?
index=web earliest=-30m
| iplocation clientip
| stats count dc(clientip) as unique_ips by Country, as_org
| sort - count
```
```
# Uniformity check — bots look identical
index=web earliest=-30m
| stats count dc(clientip) as clients by http_user_agent
| sort - count
| head 20
```

## Step 3 — Decision tree
```
Service degradation reported
│
├─ Is it actually an attack? (Step 1)
│   └─ NO → hand to Ops/Application as a performance incident. Close the SIR
│           with an accurate reason. Do not leave it as "DDoS" — that pollutes
│           your metrics and your threat picture.
│
├─ Which layer? (Step 2)
│   ├─ L3/L4 volumetric → ENGAGE ISP / SCRUBBING PROVIDER IMMEDIATELY.
│   │                     Your edge cannot help. Have the contact and account
│   │                     number pre-staged; find that out today, not during.
│   └─ L7 → you can mitigate. Continue.
│
├─ Is the source concentrated or distributed?
│   ├─ Few sources     → block at the edge, done
│   ├─ Distributed but
│   │  geographically
│   │  concentrated    → geo-block if you have no legitimate users there
│   └─ Widely distributed → rate limiting, JS challenge / CAPTCHA at the CDN,
│                           behavioural rules. IP blocking will not scale.
│
├─ Is there a distinguishing request signature?
│   ├─ YES → WAF rule on the signature. Fastest and least collateral damage.
│   └─ NO  → rate limiting and challenges; accept some legitimate-user friction
│
├─ SMOKESCREEN CHECK — run this every time, no exceptions
│   → While everyone watches the traffic graph, check for concurrent intrusion:
│     new admin logins, data egress, new accounts, authentication anomalies.
│     DDoS is used as cover. This check takes two minutes and has caught real
│     intrusions. See Q13.1.
│
└─ Is there an extortion demand?
    └─ YES → Legal + Exec. Do not respond to the attacker. Preserve the demand
             as evidence. Note that ransom DDoS threats are frequently bluffs,
             but that assessment is not the SOC's to make alone.
```

**Q13.1 — Smokescreen check (run during every DDoS)**
```
index=azure_ad sourcetype="azure:aad:signin" earliest=-4h "status.errorCode"=0
| lookup corporate_ip_ranges.csv cidr as ipAddress OUTPUT description as corp_site
| where isnull(corp_site)
| stats count values(appDisplayName) as apps by userPrincipalName, ipAddress, "location.countryOrRegion"
| sort - count
```
```
index=proxy earliest=-4h
| stats sum(bytes_out) as bytes_out by user, dest_host
| eval GB=round(bytes_out/1024/1024/1024,2)
| where GB > 1
| sort - GB
```
```
index=wineventlog earliest=-4h EventCode IN (4720, 4728, 4732, 4756)
| table _time, EventCode, Account_Name, Member_Name, Group_Name, Subject_Account_Name
```

## Step 4 — Mitigation options
| Option | Effect | Trade-off |
|---|---|---|
| **Upstream scrubbing (ISP / Azure DDoS / Cloudflare / Akamai)** | Only real answer to volumetric | Needs pre-existing contract and contacts. Establish this before you need it. |
| **CDN in front of origin** | Absorbs L7, caches, hides origin IP | If origin IP is already known to the attacker, changing it may be necessary too |
| **WAF signature rule** | Precise, low collateral | Requires a distinguishing signature |
| **Rate limiting per IP / per session** | Broad protection | Hurts users behind shared NAT (mobile carriers, large offices) |
| **JS challenge / CAPTCHA** | Very effective against non-browser bots | Accessibility impact; friction for real users; **note that Claude and other automated agents cannot solve CAPTCHAs, so this is a manual control** |
| **Geo-blocking** | Cheap, effective if applicable | Blocks legitimate travellers and VPN users |
| **Scale out / autoscale** | Absorbs the attack | Costs money; the attacker may be optimising for exactly that (economic DoS) |
| **Drop the affected endpoint** | Protects the rest of the service | Feature outage — business decision, not SOC's alone |
| **Blackhole the target IP** | Protects everything else | Completes the attacker's objective for that IP. Last resort. |

## Step 5 — Communications
This is the runbook where comms matter as much as the technical response.
- Status page updated within 15 minutes of confirming customer impact
- Exec brief every 30 minutes while degraded
- Support/service desk given a holding statement so they're not improvising
- Do not publish attack specifics or mitigation details while the attack is live — the attacker reads your status page and will adapt
- Post-incident: publish an honest summary; vague statements erode trust more than the outage did

## Step 6 — Verification and follow-up
- [ ] Attack vs failure correctly determined and recorded
- [ ] Layer classified; correct mitigation owner engaged
- [ ] Smokescreen check completed (Q13.1) — **document that you ran it**
- [ ] Service restored and confirmed by synthetic monitoring, not just by traffic graphs
- [ ] Attack signature and source data preserved for the provider and for law enforcement if applicable
- [ ] Extortion demand (if any) handed to Legal, not answered
- [ ] Peak attack volume recorded (informs future scrubbing capacity sizing)
- [ ] Origin IP exposure reviewed — if the origin was hit directly behind a CDN, the origin IP leaked and needs rotating
- [ ] Pre-staged contacts and runbook updated with anything you had to find out during the incident

## Step 7 — ServiceNow
Category `Denial of Service`. Link to Major Incident if customer-facing.
Record peak bandwidth/request rate, duration, mitigation used, and the smokescreen check result.
If it turned out not to be an attack, reclassify honestly and route to the right team — accurate incident data is worth more than a tidy-looking DDoS count.
