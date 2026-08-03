# APPLICATION, CLOUD & THIRD-PARTY RUNBOOKS
### PB-11 Web Application Attack · PB-12 Vulnerability Exploitation · PB-14 Cloud & SaaS Misconfiguration · PB-17 Third-Party Compromise

---
---

# PB-11 · Web Application Attack / Internet-Facing Exploitation

**Default priority:** P3 for probing · **P2** for sustained targeted attack · **P1** the moment exploitation succeeds

## Step 1 — The question that determines everything: did it work?

Attack *attempts* against internet-facing applications are constant background noise. Do not triage volume; triage **outcome**.

```
# Attempts (noise) vs successes (incidents)
index=web earliest=-24h clientip="203.0.113.50"
| stats count by status, uri_path, bytes
| sort - count
```

**Success indicators:**
| Pattern | Meaning |
|---|---|
| Long run of 400/403/500, then a **200** on the same attack path | Exploitation succeeded on that attempt |
| Response `bytes` far larger than normal for that endpoint | Data returned — likely SQLi extraction |
| 200 response to a request containing obvious injection syntax | The application processed it |
| A new URL path appearing that isn't in your application's route list | **Webshell.** P1. |
| POST to a path that only ever received GETs | Upload or command execution |
| 302 to an admin path from an unauthenticated session | Auth bypass |
| Server-side timing: `sleep(5)` payloads with 5-second responses | Blind SQLi confirmed working |

**The definitive check is on the server, not in the web log:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("w3wp.exe","httpd.exe","httpd","nginx.exe","nginx",
        "tomcat9.exe","java.exe","php-cgi.exe","php-fpm","node.exe","ruby.exe","python.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","bash","sh","dash","whoami.exe",
        "whoami","net.exe","net1.exe","ipconfig.exe","systeminfo.exe","netstat.exe",
        "curl","curl.exe","wget","certutil.exe","nltest.exe","tasklist.exe","hostname.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName,
          ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp asc
```
**A web server process spawning a shell is confirmed compromise. P1. No further debate required.**

## Step 2 — Decision tree
```
Web application attack detected
│
├─ Did it succeed? (Step 1)
│   ├─ NO, all attempts blocked/failed
│   │   → P3/P4. Block the source, verify WAF coverage, patch if a real
│   │     vulnerability was probed. Do not open a P2 for scanner noise.
│   │     Record it — repeated targeted probing of one specific endpoint is
│   │     reconnaissance and may precede a real attempt.
│   └─ YES → P1. Continue.
│
├─ What did they achieve?
│   ├─ Data read (SQLi extraction)          → DATA BREACH. Determine what tables/records.
│   │                                          Legal. PB-10 assessment.
│   ├─ Command execution (shell spawned)     → SERVER COMPROMISE. PB-02 on the host.
│   │                                          Rotate every secret on/reachable from it.
│   ├─ File upload (webshell)                → PERSISTENT ACCESS. Find every webshell (Q11.4),
│   │                                          not just the one you know about.
│   ├─ Authentication bypass                 → check what was accessed as which user
│   ├─ SSRF                                  → check cloud instance metadata access (Q11.6).
│   │                                          IMDS access = cloud credentials stolen → PB-14.
│   ├─ Stored XSS                             → user-session impact; check for admin
│   │                                          session theft
│   └─ Defacement                             → visible; comms needed; but check for the
│                                                quieter compromise underneath it
│
├─ Is the vulnerability a known CVE or a bug in your own code?
│   ├─ Known CVE → PB-12 as well. Check whether other instances are vulnerable.
│   └─ Own code  → engage the development team. Emergency fix + code review.
│
├─ Are secrets on that host? (almost always yes)
│   → DB connection strings, API keys, service account credentials, cloud IAM
│     role/instance credentials, certificates, .env files, config files.
│     ALL OF THESE ARE NOW COMPROMISED. Rotating them is not optional and is
│     the step most often deferred and forgotten.
│
└─ Is the host a pivot into the internal network?
    → DMZ-to-internal reachability check. If the web server can reach internal
      systems, run PB-08. This is how external compromise becomes internal.
```

## Step 3 — Queries

**Q11.1 — Attack pattern detection**
```
index=web earliest=-24h
| eval decoded=lower(urldecode(uri_query)), decoded_path=lower(urldecode(uri_path))
| eval body=lower(coalesce(form_data, post_body, ""))
| eval attack=case(
    match(decoded." ".body,"union\s+(all\s+)?select|information_schema|sleep\(|benchmark\(|pg_sleep|waitfor\s+delay|'\s+or\s+'?1'?='?1|\bxp_cmdshell\b"),"SQLi",
    match(decoded." ".body,"<script|javascript:|onerror\s*=|onload\s*=|<iframe|<svg|document\.cookie|alert\("),"XSS",
    match(decoded.decoded_path,"\.\./\.\.|\.\.%2f|etc/passwd|windows/win\.ini|boot\.ini|proc/self/environ"),"PathTraversal",
    match(decoded." ".body,";\s*(cat|ls|id|whoami|curl|wget|nc|bash|sh)\s|\|\s*(cat|ls|id|whoami)|\$\(|`.*`"),"CommandInjection",
    match(decoded." ".body,"\$\{jndi:|\$\{lower:|\$\{env:|\$\{sys:"),"Log4Shell",
    match(decoded." ".body,"\{\{.*\}\}|\$\{.*\}|<%=|__proto__|constructor\.prototype"),"TemplateInjection/Prototype",
    match(decoded." ".body,"file://|dict://|gopher://|169\.254\.169\.254|metadata\.google|100\.100\.100\.200"),"SSRF",
    match(decoded." ".body,"o:\d+:\"|rO0AB|aced0005|__reduce__|pickle"),"Deserialization",
    true(),"other")
| where attack!="other"
| stats count values(status) as statuses values(uri_path) as paths
        min(_time) as firstTime max(_time) as lastTime
        by clientip, attack, useragent
| convert ctime(firstTime) ctime(lastTime)
| sort - count
```

**Q11.2 — Success isolation (the query that matters)**
```
index=web earliest=-24h clientip="203.0.113.50" status IN (200, 201, 302)
| eval decoded=lower(urldecode(uri_query))
| where match(decoded,"union|select|\.\./|<script|jndi:|;\s*(cat|whoami|id)")
| table _time, clientip, http_method, uri_path, uri_query, status, bytes, useragent
| sort _time
```
Any row here is a successful exploitation attempt. Treat each as confirmed.

**Q11.3 — Scanner vs targeted actor**
```
index=web earliest=-24h clientip="203.0.113.50"
| stats dc(uri_path) as paths count as requests dc(useragent) as agents
        values(useragent) as agent_list
        min(_time) as firstTime max(_time) as lastTime by clientip
| eval duration_min=round((lastTime-firstTime)/60,1),
       rate=round(requests/(duration_min+0.1),1)
| convert ctime(firstTime) ctime(lastTime)
```
| Profile | Read as |
|---|---|
| Hundreds of distinct paths, high rate, scanner UA (`sqlmap`, `nuclei`, `nikto`, `acunetix`, `zgrab`) | Automated scanning. P3/P4. Block and move on. |
| Few paths, low rate, browser-like UA, over hours or days | **Targeted human.** More dangerous even with fewer requests. Investigate properly. |
| Requests only to endpoints that genuinely exist in your app | They did reconnaissance, or they have your source/API docs |
| Traffic from Tor exits or a residential proxy pool | Deliberate anonymisation. Weight toward targeted. |

**Q11.4 — Webshell hunt (find them all, not just the first)**
```kql
DeviceFileEvents
| where Timestamp > ago(30d) and ActionType in ("FileCreated","FileModified")
| where FolderPath has_any (@"inetpub\wwwroot", @"\webapps\", "/var/www/", @"\htdocs\",
        @"\wwwroot\", "/usr/share/nginx/html", @"\App_Data\", @"\bin\")
| where FileName endswith_any (".aspx",".asp",".ashx",".asmx",".php",".php5",".phtml",
        ".jsp",".jspx",".jsw",".war",".cfm",".cgi",".pl",".py",".dll")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, FileSize,
          InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp desc
```
**Then verify against a known-good baseline.** A file list alone doesn't tell you what's malicious — you need to diff against your deployment manifest or a clean build. If you don't have a baseline for your web roots, creating one is the top follow-up action from this incident.
```bash
# On the host (via Live Response or ops), files newer than the last deployment
find /var/www -type f -newermt "2026-07-15" \
    \( -name "*.php" -o -name "*.jsp" -o -name "*.aspx" \) -ls
```
Also check for webshells hidden inside legitimate files (appended code at the end of an existing index.php) — a file-creation query will miss those. `FileModified` on files you didn't deploy is the signal.

**Q11.5 — Timeline reconstruction on the server**
```kql
let host = "WEBSRV01";
let t0 = datetime(2026-07-30 14:00);
union
 (DeviceProcessEvents | where DeviceName =~ host and Timestamp > t0
    | project Timestamp, Type="Process", Detail=ProcessCommandLine, Parent=InitiatingProcessFileName, Account=AccountName),
 (DeviceFileEvents    | where DeviceName =~ host and Timestamp > t0
    | project Timestamp, Type="File", Detail=strcat(ActionType," ",FolderPath,FileName), Parent=InitiatingProcessFileName, Account=InitiatingProcessAccountName),
 (DeviceNetworkEvents | where DeviceName =~ host and Timestamp > t0
    | project Timestamp, Type="Network", Detail=strcat(RemoteIP,":",tostring(RemotePort)," ",RemoteUrl), Parent=InitiatingProcessFileName, Account=InitiatingProcessAccountName),
 (DeviceRegistryEvents| where DeviceName =~ host and Timestamp > t0
    | project Timestamp, Type="Registry", Detail=strcat(RegistryKey,"\\",RegistryValueName), Parent=InitiatingProcessFileName, Account="")
| order by Timestamp asc
```

**Q11.6 — SSRF to cloud metadata (steals cloud credentials — check every SSRF)**
```
index=web earliest=-7d
| eval decoded=urldecode(uri_query)
| search decoded IN ("*169.254.169.254*","*metadata.google.internal*","*100.100.100.200*",
                     "*metadata.azure.com*","*169.254.170.2*")
| table _time, clientip, uri_path, uri_query, status, bytes
```
A 200 with meaningful bytes to a metadata endpoint means **cloud instance credentials were retrieved.** Rotate the instance role/managed identity immediately and check for its use in cloud audit logs → PB-14.

## Step 4 — Containment options
| Option | Effect | Trade-off |
|---|---|---|
| **WAF rule on the attack signature** | Fast, precise, keeps the app up | Best first move if you have a signature |
| **Block source IP/ASN** | Stops that actor | They rotate; buys time only |
| **Rate limit the endpoint** | Reduces exploitability | Doesn't fix the vulnerability |
| **Disable the vulnerable endpoint/feature** | Removes the vulnerability | Feature outage — business decision |
| **Take the application offline** | Definitive | Only for active exploitation of a critical vuln with no other mitigation. Business decision with exec sign-off. |
| **Isolate the server** | Stops the pivot | Causes an outage. For a web farm, remove the node from the load balancer instead — cleaner. |
| **Remove from load balancer pool** | Contains one node, keeps the service up | **Preferred for web farms.** Do this before isolating. |
| **Emergency patch** | Fixes the root cause | Requires a Change; do it under emergency change process |

**Secret rotation after any server compromise — do all of these:**
- Database connection strings and DB user passwords
- Application API keys and third-party integration tokens
- Cloud IAM role / managed identity / instance profile credentials
- TLS private keys if the key material was on the host
- Service account passwords
- Any secrets in `.env`, `web.config`, `appsettings.json`, `application.properties`
- Session signing keys / JWT secrets (an attacker with these can forge sessions indefinitely — this one is very commonly missed)

## Step 5 — Verification
- [ ] Exploitation success definitively determined (not assumed either way)
- [ ] Server-side check performed (process spawning), not just web log analysis
- [ ] Every webshell found — diffed against a deployment baseline, including modified files
- [ ] Full server timeline built (Q11.5)
- [ ] SSRF-to-metadata checked (Q11.6) if SSRF was possible
- [ ] All secrets rotated per the list above, including JWT/session keys
- [ ] Vulnerability patched or mitigated; fix verified by retesting the original payload
- [ ] Data access assessed — what could the attacker read
- [ ] DMZ-to-internal pivot checked (PB-08)
- [ ] Other instances of the same application checked for the same vulnerability
- [ ] WAF coverage gap raised — why didn't it catch this
- [ ] Web root baseline created if it didn't exist

## Step 6 — ServiceNow
Category `Web Application Attack` · Subcategory by technique. P1 on confirmed exploitation.
Link the application CI and the server CI. Raise a linked Problem record for the vulnerability and a Change for the fix.
Close notes: exploitation confirmed/not, technique, what was achieved, secrets rotated (list them), patch status.

---
---

# PB-12 · Vulnerability Exploitation / Unpatched Systems

**Default priority:** P1 if internet-facing and on the CISA KEV list · P2 internal or non-KEV · P3 if not actually exposed

**Trigger:** new critical CVE announced, vulnerability scanner finding on an exposed asset, threat intel on active exploitation, or discovery during another incident.

## Step 1 — Confirm you're actually vulnerable
Scanner findings are frequently wrong. Version banners lie. Confirm before you mobilise.

```kql
DeviceTvmSoftwareVulnerabilities
| where CveId == "CVE-2026-XXXXX"
| project DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion,
          VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| order by DeviceName asc
```
```kql
DeviceTvmSoftwareInventory
| where SoftwareName has "<product>"
| summarize Devices=dcount(DeviceName), Versions=make_set(SoftwareVersion,20) by SoftwareName, SoftwareVendor
```
Then verify: is the vulnerable component/module actually enabled? Is the vulnerable configuration in use? Many CVEs require a non-default setting. Check the vendor advisory's preconditions, not just the version number.

## Step 2 — Decision tree
```
Critical vulnerability identified
│
├─ Are we actually vulnerable? (Step 1)
│   ├─ NO / not exposed configuration → document why, close P4. Record the reasoning
│   │   so the next person doesn't redo the work.
│   └─ YES → continue
│
├─ Exposure assessment
│   ├─ Internet-facing, unauthenticated exploit    → P1. Hours, not days.
│   ├─ Internet-facing, authenticated required     → P2
│   ├─ Internal only, unauthenticated              → P2
│   ├─ Internal, requires local access/privilege   → P3
│   └─ Not reachable by any untrusted party        → P3/P4, normal patch cycle
│
├─ Exploitation status
│   ├─ On CISA KEV / confirmed active exploitation → treat as P1 if exposed at all
│   ├─ Public PoC available                        → assume exploitation within days
│   ├─ Weaponised in a commercial toolkit /
│   │  ransomware affiliate use reported           → P1
│   └─ Theoretical only, no PoC                    → normal emergency patch cycle
│
├─ HAVE WE ALREADY BEEN EXPLOITED? (Step 3)
│   │  Run this BEFORE you patch. Patching destroys evidence and, worse,
│   │  can leave an attacker's persistence in place while you declare victory.
│   ├─ YES → this is an intrusion, not a vulnerability. Go to PB-11 / PB-02 / PB-08.
│   │        Patching alone does not evict an attacker who is already inside.
│   └─ NO (with a documented search) → proceed to remediation
│
├─ Can we patch now?
│   ├─ YES → emergency change, patch, verify
│   └─ NO (no patch available, or patching requires an outage window)
│       → compensating controls, ranked:
│         1. Remove internet exposure (firewall / take offline) — most effective
│         2. WAF virtual patch on the exploit signature
│         3. Disable the vulnerable feature/module
│         4. Network ACL to restrict who can reach it
│         5. Enhanced monitoring on the specific exploit signature (detection, not prevention —
│            be honest with the business that this is not a fix)
│
└─ Fleet scope
    → How many instances? Are any unmanaged/forgotten? Shadow IT instances of
      the same product are the ones that get exploited. Check DNS, certificate
      transparency logs, and external scan data, not just your CMDB.
```

## Step 3 — Compromise assessment before patching

**Q12.1 — Exploitation attempts in web logs**
```
index=web earliest=-90d
| eval decoded=lower(urldecode(uri_query)).lower(urldecode(uri_path))
| search decoded="*<CVE-specific payload pattern>*"
| stats count values(status) as statuses min(_time) as firstTime max(_time) as lastTime
        by clientip, uri_path
| convert ctime(firstTime) ctime(lastTime)
| sort firstTime
```
Search back to the earliest date the vulnerability existed in your environment, not just 7 days. Edge-device vulnerabilities are often exploited weeks before disclosure.

**Q12.2 — Post-exploitation indicators on the vulnerable host**
```kql
let host = "EDGE01";
DeviceProcessEvents
| where DeviceName =~ host and Timestamp > ago(90d)
| where InitiatingProcessFileName in~ ("w3wp.exe","java.exe","nginx.exe","httpd.exe","node.exe","python.exe")
     or AccountName in~ ("nobody","www-data","apache","iis apppool\\defaultapppool","nt authority\\network service")
| where FileName in~ ("cmd.exe","powershell.exe","bash","sh","whoami.exe","curl","wget","certutil.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| order by Timestamp asc
```
```kql
// New files in application directories
DeviceFileEvents
| where DeviceName =~ "EDGE01" and Timestamp > ago(90d) and ActionType == "FileCreated"
| where FolderPath has_any ("/tmp","/var/tmp","/dev/shm", @"\Temp", @"\wwwroot", @"\webapps")
| project Timestamp, FileName, FolderPath, SHA256, InitiatingProcessFileName
| order by Timestamp asc
```
```kql
// Outbound connections from a device that should mostly receive, not initiate
DeviceNetworkEvents
| where DeviceName =~ "EDGE01" and Timestamp > ago(90d) and ActionType == "ConnectionSuccess"
| where not(ipv4_is_private(RemoteIP))
| summarize Connections=count(), FirstSeen=min(Timestamp) by RemoteIP, RemotePort, InitiatingProcessFileName
| order by FirstSeen asc
```

**For appliances with no EDR agent** (VPN concentrators, firewalls, load balancers, NAS, hypervisors — which is where most of the serious edge exploitation happens):
- Follow the vendor's specific compromise-assessment guidance. Reputable vendors publish one alongside the advisory; use it.
- Collect and review config for unauthorised changes, added admin accounts, new SSH keys, modified scripts
- Check the appliance's own logs for authentication anomalies
- Compare running config against your last known-good backup
- **Assume compromise if the device was exposed and unpatched during a known active-exploitation window.** For appliances, a factory reset and rebuild from known-good config is often the only defensible remediation — patching a compromised appliance leaves the implant in place. This has been the pattern for essentially every major edge-device campaign.

## Step 4 — Remediation options
| Option | Speed | Effectiveness |
|---|---|---|
| **Remove internet exposure** | Minutes | Complete, while it lasts. Best emergency control. |
| **Patch** | Hours–days | Complete. The actual fix. |
| **WAF virtual patch** | Hours | Good for web vulns with a clear signature |
| **Disable the vulnerable module/feature** | Hours | Complete for that vector |
| **Network ACL restriction** | Hours | Good; reduces the attacker population |
| **Upgrade/replace the appliance** | Days–weeks | Needed when the product is EOL with no patch |
| **Enhanced monitoring only** | Hours | **Detection, not prevention.** Acceptable as a bridge; must be labelled honestly to the business as accepting risk, with a named risk acceptor and a date. |

## Step 5 — Verification
- [ ] Vulnerability confirmed present (not just scanner-reported)
- [ ] Exposure assessed accurately (internet-facing? auth required? config precondition met?)
- [ ] KEV / active-exploitation status checked
- [ ] **Compromise assessment completed before patching**, and documented
- [ ] Full fleet inventory — including unmanaged and shadow instances found via external means
- [ ] Patch or compensating control applied and **verified by retesting the exploit condition**, not just by version number
- [ ] If compromise found: pivoted to the appropriate intrusion runbook; appliance rebuilt rather than patched
- [ ] Detection created for the exploit signature (durable value beyond this CVE)
- [ ] Secrets on the affected host rotated if compromise couldn't be ruled out
- [ ] Risk acceptance documented and signed if remediation is deferred

## Step 6 — ServiceNow
Category `Vulnerability` — or `Intrusion` if exploitation is found. Raise a Change for the patch and track it to completion. Do not close the SIR on "patch scheduled"; close it on "patch verified."
Link to a Problem record if the root cause is a patching-process gap rather than this one CVE.

---
---

# PB-14 · Cloud / SaaS Misconfiguration & Abuse

**Default priority:** P2 · **P1** if data was publicly exposed and accessed, or if identity/IAM was modified

**Detection sources:** Defender for Cloud recommendations and alerts, Defender for Cloud Apps, Entra audit logs, cloud provider activity logs in Splunk, external notification ("your bucket is public").

## Step 1 — Decision tree
```
Cloud misconfiguration or suspicious cloud activity
│
├─ Category?
│   ├─ EXPOSURE (public storage, open security group, disabled logging, public snapshot)
│   ├─ IDENTITY (new service principal, role grant, key created, MFA disabled)
│   ├─ RESOURCE ABUSE (crypto-mining, unexpected regions, cost spike)
│   └─ DATA (mass download, external sharing, unusual API access)
│
├─ For EXPOSURE — the only question that matters:
│   │  WAS IT ACCESSED? (Q14.4)
│   ├─ NO evidence of access → near-miss. P3. Fix, verify logging was actually
│   │   enabled (if it wasn't, you CANNOT say it wasn't accessed — say
│   │   "no evidence" and flag the logging gap as the real finding).
│   └─ YES, accessed by an unknown party → DATA BREACH. P1. Legal. PB-10 assessment.
│       Determine what was accessed, by whom, when, how much.
│
├─ For IDENTITY — was the change authorized?
│   ├─ Matching change record → verify it authorises exactly this. Close.
│   └─ NO record → P1. Treat as compromise of the actor.
│       │
│       ├─ Made by a USER    → PB-04 on that user
│       ├─ Made by a SERVICE PRINCIPAL → the SP's credentials are compromised.
│       │   Rotate its secret/certificate. Check everything it did.
│       │   Service principals are the most common blind spot here — they have
│       │   no MFA, often broad permissions, and long-lived secrets.
│       └─ New SP or app registration created → likely attacker persistence.
│           Check its granted permissions and consent. Delete it.
│
├─ For RESOURCE ABUSE
│   ├─ Compute in unusual regions, GPU instances, sudden cost spike
│   │   → cryptomining via compromised credentials. Find the credential
│   │     that created it, rotate it, delete the resources, check how it leaked
│   │     (committed to a repo? phished? exposed in a log?).
│   └─ Check for leaked keys in public repos — this is the most common cause.
│
└─ Is the affected identity/role privileged in the cloud tenant?
    └─ YES → P1. Global Admin, Owner, or a role that can grant roles = tenant
             takeover potential. Full audit of its actions.
```

## Step 2 — Queries

**Q14.1 — Azure control-plane changes**
```
index=azure sourcetype="azure:activity" earliest=-7d
  operationName.value IN (
    "Microsoft.Storage/storageAccounts/write",
    "Microsoft.Storage/storageAccounts/blobServices/containers/write",
    "Microsoft.Network/networkSecurityGroups/securityRules/write",
    "Microsoft.Authorization/roleAssignments/write",
    "Microsoft.Authorization/policyAssignments/delete",
    "Microsoft.KeyVault/vaults/accessPolicies/write",
    "Microsoft.KeyVault/vaults/secrets/write",
    "Microsoft.Insights/diagnosticSettings/delete",
    "Microsoft.Compute/virtualMachines/write",
    "Microsoft.Compute/disks/beginGetAccess/action")
| table _time, caller, callerIpAddress, operationName.value, resourceId,
        resultType, properties.statusCode
| sort _time
```
> `Microsoft.Insights/diagnosticSettings/delete` — **someone turning off logging is one of the highest-signal events in cloud security.** Legitimate reasons exist but are rare. Always investigate.

**Q14.2 — Entra ID application and service principal changes**
```
index=azure_ad sourcetype="azure:aad:audit" earliest=-30d
  operationName IN ("Add service principal","Update service principal",
    "Add service principal credentials","Update application – Certificates and secrets management",
    "Add app role assignment to service principal","Consent to application",
    "Add OAuth2PermissionGrant","Add delegated permission grant",
    "Add owner to application","Add owner to service principal",
    "Update application","Delete service principal")
| eval actor=coalesce('initiatedBy.user.userPrincipalName','initiatedBy.app.displayName'),
       target='targetResources{}.displayName'
| table _time, operationName, target, actor, "targetResources{}.modifiedProperties{}.newValue", result
| sort _time
```
**"Add service principal credentials"** = someone added a new secret or certificate to an existing app. That's persistence: the attacker can now authenticate as that application indefinitely, with no MFA and no user interaction. It survives every user-focused containment action. Check this on every cloud incident.

**Q14.3 — Defender for Cloud Apps / unified cloud activity**
```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType has_any ("Add service principal","Add OAuth2PermissionGrant","Consent to application",
        "Update application","Remove policy","Delete policy","Set-Mailbox","Add member to role",
        "UpdateApplication","AddServicePrincipalCredentials","Disable Strong Authentication")
| project Timestamp, Application, ActionType, AccountDisplayName, AccountObjectId,
          IPAddress, IsAdminOperation, ObjectName, RawEventData
| order by Timestamp desc
```

**Q14.4 — Was the exposed resource actually accessed? (the breach-determining query)**
```
index=azure sourcetype="azure:storage:blob" earliest=-90d
  AuthenticationType="Anonymous" OR AuthenticationType="SAS"
| lookup corporate_ip_ranges.csv cidr as CallerIpAddress OUTPUT description as corp_site
| where isnull(corp_site)
| stats count dc(ObjectKey) as unique_objects values(OperationName) as ops
        sum(ResponseBodySize) as bytes_out
        min(_time) as firstTime max(_time) as lastTime
        by CallerIpAddress, UserAgentHeader
| eval GB=round(bytes_out/1024/1024/1024,3)
| convert ctime(firstTime) ctime(lastTime)
| sort - unique_objects
```
**If storage diagnostic logging was not enabled, you cannot answer this question.** Say exactly that to Legal — "logging was not enabled for this resource, so access cannot be determined" — rather than implying no access occurred. The logging gap then becomes the priority finding.

**Q14.5 — Resource abuse / cryptomining**
```
index=azure sourcetype="azure:activity" earliest=-30d
  operationName.value="Microsoft.Compute/virtualMachines/write"
| rex field=resourceId "resourceGroups/(?<rg>[^/]+)"
| stats count values(rg) as resource_groups values(properties.responseBody) as details
        by caller, callerIpAddress, resourceLocation
| sort - count
```
Compare `resourceLocation` against your approved regions list. Resource creation in a region you don't use is one of the cleanest cloud-compromise signals available.

**Q14.6 — Leaked credential hunt (find the root cause)**
The usual causes of cloud credential compromise, in rough order of frequency: committed to a public or internal repo, embedded in a mobile app or client-side JS, exposed in a log or error page, phished from an engineer, left in a public CI/CD artifact, retrieved via SSRF from instance metadata (→ PB-11 Q11.6).
```kql
// Where has this credential/SP been used from?
CloudAppEvents
| where Timestamp > ago(90d)
| where AccountObjectId == "<service principal object id>"
| summarize Events=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp),
            Actions=make_set(ActionType,20) by IPAddress
| order by FirstSeen asc
```
The first non-corporate IP is roughly when the credential leaked.

## Step 3 — Containment options
| Option | When | Notes |
|---|---|---|
| **Revert the misconfiguration** | Always | But capture the before-state as evidence first |
| **Rotate the exposed keys/secrets/SAS tokens** | Always if any credential was exposed | Includes storage account keys, SAS tokens, SP secrets and certificates, API keys |
| **Delete rogue service principals / app registrations** | Attacker-created | Check their granted permissions first, to understand what they had access to |
| **Remove added SP credentials** | Attacker added a secret to a legitimate app | Easy to miss. Check every app the actor touched. |
| **Disable the compromised identity** | User or SP compromise | For SPs, disabling may break production — coordinate |
| **Delete the abused resources** | Mining VMs etc. | Snapshot one for evidence before deleting |
| **Conditional Access / policy guardrail** | Durable prevention | Raise as a Change |
| **Policy-as-code guardrail (Azure Policy, deny effect)** | Prevents recurrence | The real fix. Detection without prevention means this recurs. |
| **Re-enable and expand logging** | Whenever a logging gap was found | Highest-value follow-up in most cloud incidents |

## Step 4 — Verification
- [ ] Misconfiguration reverted; before-state captured
- [ ] Access determination made (Q14.4) — or the logging gap explicitly documented
- [ ] All exposed credentials rotated, including SAS tokens and SP secrets/certs
- [ ] Service principal review completed — no attacker-added credentials remain
- [ ] Root cause of any credential leak identified (Q14.6)
- [ ] Actor's full action set audited
- [ ] Rogue resources deleted; one preserved for evidence if relevant
- [ ] Preventive guardrail (policy-as-code / CA policy) raised as a Change — **without this, the same incident recurs**
- [ ] Logging enabled and verified on the affected resource type across the tenant
- [ ] Legal briefed if data exposure occurred

## Step 5 — ServiceNow
Category `Cloud Misconfiguration` or `Cloud Account Compromise`. Link the cloud resource CI.
Close notes must state whether access occurred, or that it could not be determined and why.
Every PB-14 should produce a guardrail Change. Fixing one bucket without fixing the policy that allowed it is not closure.

---
---

# PB-17 · Third-Party / Supply Chain Compromise

**Default priority:** P1 if the vendor has network access, privileged access, or holds your regulated data · P2 otherwise

**Trigger:** vendor notifies you of their breach; you detect malicious activity from vendor access; a vendor's software update is compromised; a vendor appears in breach news.

## Step 1 — Enumerate the exposure (do this before anything else, and be exhaustive)

You cannot contain what you haven't enumerated, and organizations consistently underestimate vendor access. Check every one of these:

| Access type | Where to check |
|---|---|
| Named user accounts for vendor staff | Entra ID / AD — filter by vendor domain, guest accounts, and accounts with vendor naming conventions |
| Guest / B2B accounts | Entra → Users → filter User type = Guest |
| Service accounts used by vendor tooling | AD service accounts, Entra SPs |
| Service principals / app registrations | Entra → Enterprise applications, App registrations |
| OAuth consents to vendor apps | Entra → Enterprise applications → Permissions |
| Site-to-site VPN / IPsec tunnels | Firewall config |
| Remote access (RMM, jump box, Citrix, VDI) | PB-15 tooling inventory |
| API keys and integration tokens | Your secrets store, application configs |
| SFTP / file transfer accounts | File transfer platform |
| Data held by the vendor | Vendor contract, data processing agreement, DPIA records |
| Their software running in your estate | Software inventory (Q17.1) |
| Their hardware/appliances | CMDB |
| Physical access badges | Physical security system |
| Shared mailboxes / Teams guest access | Exchange, Teams admin |

**Do this enumeration now, as a project, before an incident.** Doing it under time pressure at P1 is how things get missed.

## Step 2 — Decision tree
```
Third-party compromise
│
├─ What type?
│   ├─ VENDOR BREACHED (their systems compromised, your access/data at risk)
│   ├─ VENDOR ACCESS ABUSED (attacker using vendor credentials into your estate)
│   ├─ SOFTWARE SUPPLY CHAIN (compromised update/library/package shipped to you)
│   └─ VENDOR HOLDS YOUR DATA (breach of data they process for you)
│
├─ For VENDOR BREACHED / ACCESS ABUSED
│   ├─ SUSPEND ALL VENDOR ACCESS immediately (Step 3)
│   │   → Do this before you finish the investigation. Vendor downtime is
│   │     cheaper than a domain compromise. Tell the vendor you've done it.
│   ├─ Hunt for activity via vendor identities/IPs (Q17.2)
│   ├─ Any suspicious activity found? → treat as intrusion, run PB-04/PB-08
│   └─ Rotate every shared credential (Step 3)
│
├─ For SOFTWARE SUPPLY CHAIN
│   ├─ Which versions are affected, and which do we run? (Q17.1)
│   ├─ Hunt the vendor-published IoCs across the estate
│   ├─ Block the update channel temporarily — otherwise you may pull the
│   │   malicious update mid-incident
│   ├─ Assume the software's privilege level = the attacker's privilege level.
│   │   Agents and management tools typically run as SYSTEM/root. That is a
│   │   worst-case starting point.
│   └─ Rebuild rather than clean where the software ran with high privilege
│
├─ For VENDOR HOLDS YOUR DATA
│   ├─ What data, how much, whose → Legal owns notification.
│   │   You are likely the data controller even though they were breached;
│   │   your notification obligation is usually yours, not theirs.
│   ├─ Demand written specifics: what was accessed, when, how, by whom
│   └─ Do not accept "we are investigating" as a final answer. Set a deadline
│       and escalate commercially through your vendor manager.
│
└─ Are other vendors exposed the same way?
    → If the root cause was a shared platform (a widely used MFT product,
      a common RMM, a popular library), check every vendor that uses it.
      Supply chain incidents rarely affect one relationship.
```

## Step 3 — Containment actions

**Suspend access — all of it, at once:**
```powershell
# Disable all vendor guest accounts and revoke their sessions
Connect-MgGraph -Scopes "User.ReadWrite.All","Directory.ReadWrite.All"
$vendorDomain = "vendor.com"
Get-MgUser -All -Filter "userType eq 'Guest'" |
  Where-Object { $_.UserPrincipalName -like "*$($vendorDomain.Replace('.','_'))*" -or
                 $_.Mail -like "*@$vendorDomain" } |
  ForEach-Object {
    Write-Host "Disabling $($_.UserPrincipalName)"
    Update-MgUser -UserId $_.Id -AccountEnabled:$false
    Revoke-MgUserSignInSession -UserId $_.Id
  }
```
Also: disable the site-to-site tunnel, disable vendor service accounts, revoke vendor OAuth consents, disable vendor SFTP accounts, deactivate physical badges, and remove vendor SP credentials.

**Rotate every shared secret:**
- Credentials the vendor held for your systems
- API keys issued to the vendor
- Credentials the vendor's software uses in your estate
- Shared certificates
- Any credential the vendor could have stored, including in their ticketing system

**Q17.1 — What of theirs is running in our estate?**
```kql
DeviceTvmSoftwareInventory
| where SoftwareVendor has "<vendor>"
| summarize Devices=dcount(DeviceName), DeviceList=make_set(DeviceName,100),
            Versions=make_set(SoftwareVersion,20) by SoftwareName, SoftwareVendor
```
```kql
// Their processes and what privilege they run with
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has "<vendor product>" or FileName has "<vendor product>"
| summarize Hosts=dcount(DeviceName), Accounts=make_set(AccountName,10),
            Commands=make_set(ProcessCommandLine,10) by FileName
```

**Q17.2 — All activity via vendor access**
```
index=* earliest=-90d
  (user IN ("*@vendor.com","svc_vendor*","vendor_*")
   OR src_ip IN (<vendor IP ranges>)
   OR Account_Name IN ("*vendor*"))
| stats count values(action) as actions values(sourcetype) as sourcetypes
        min(_time) as firstTime max(_time) as lastTime
        by user, src_ip, index
| convert ctime(firstTime) ctime(lastTime)
| sort firstTime
```
```kql
IdentityLogonEvents
| where Timestamp > ago(90d)
| where AccountUpn has "vendor.com" or AccountName startswith "svc_vendor"
| summarize Logons=count(), Devices=make_set(DeviceName,50), IPs=make_set(IPAddress,20)
    by AccountUpn, LogonType
```
Compare against the vendor's stated compromise window, but **search wider than the window they give you.** Vendors routinely revise their timelines outward.

**Q17.3 — Hunt vendor-published IoCs**
```kql
let badHashes = dynamic(["<sha256_1>","<sha256_2>"]);
let badDomains = dynamic(["evil1.com","evil2.com"]);
union isfuzzy=true
 (DeviceProcessEvents | where SHA256 in (badHashes)
    | project Timestamp, DeviceName, Type="ProcessExec", Detail=ProcessCommandLine),
 (DeviceFileEvents    | where SHA256 in (badHashes)
    | project Timestamp, DeviceName, Type="FileWrite", Detail=FolderPath),
 (DeviceNetworkEvents | where RemoteUrl has_any (badDomains)
    | project Timestamp, DeviceName, Type="Network", Detail=RemoteUrl)
| order by Timestamp asc
```

## Step 4 — Managing the vendor
This is half the work and it is not technical.

- Demand written, dated updates. Verbal reassurance is not evidence and won't satisfy a regulator.
- Ask specifically: what was accessed, what data of ours was involved, what is the confirmed timeline, what IoCs can you share, what is your remediation, when will access be safe to restore.
- **Do not restore access on the vendor's assurance alone.** Require evidence: their IR report or a summary of it, confirmation of credential rotation on their side, and their remediation status.
- Involve your vendor manager and Legal early — contractual notification and liability terms matter, and the commercial relationship is leverage you'll need.
- If they're unresponsive, escalate commercially. A vendor who won't give you details after a breach is itself a risk finding.
- Record everything in the SIR. This will be reviewed.

## Step 5 — Verification
- [ ] Complete exposure enumeration done (all 14 categories in Step 1)
- [ ] All vendor access suspended and verified suspended
- [ ] All shared credentials rotated
- [ ] Activity hunt completed over a window wider than the vendor's stated one
- [ ] Vendor software inventoried, and its privilege level assessed
- [ ] Vendor IoCs hunted
- [ ] Data-held-by-vendor assessment done; Legal briefed on notification obligations
- [ ] Other vendors using the same platform/product checked
- [ ] Written vendor updates obtained and attached
- [ ] Access restoration decision based on evidence, not assurance, with the decision-maker named
- [ ] Third-party risk assessment updated; contract review raised if notification terms were inadequate

## Step 6 — ServiceNow
Category `Third Party / Supply Chain`. Link the vendor record and every affected CI.
Task list: access suspension, credential rotation, activity hunt, vendor evidence collection, restoration decision, contract review.
Post Incident Review should include Procurement and the vendor manager, not just SOC. The durable fixes here are contractual and architectural: least-privilege vendor access, time-bound access, dedicated vendor accounts with no shared credentials, and notification SLAs written into contracts.
