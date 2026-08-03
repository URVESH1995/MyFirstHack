# RUNBOOK PB-01 · Phishing / Malicious Email
**Version 1.0 · Owner: SOC · Review: quarterly**
**Tools: Microsoft Defender XDR (MDO + MDE) · Splunk Cloud ES · ServiceNow SecOps (SIR)**

> **Portal navigation caveat:** Microsoft renames Defender portal menus regularly. Click paths below are written for `security.microsoft.com` and `entra.microsoft.com`. If a menu name doesn't match, use the portal search bar (top of page) with the page name — it resolves reliably even after renames.

---

## 0. Scope and roles

**Use this runbook when:** a user reports a suspicious email, MDO raises a phishing/malware alert, a Splunk notable correlates email + proxy/auth activity, or you find a malicious message during a hunt.

**Do not use this runbook for:** internal-only spam with no malicious payload (route to Service Desk), confirmed phishing *simulation* traffic (close as Benign True Positive, see §9), or vendor invoice fraud with no email compromise (route to Finance fraud process, but still check §7).

| Role | Owns |
|---|---|
| **L1 Analyst** | Intake, §1–§3 triage, containment steps marked **[L1]** |
| **L2 Analyst** | §4 scoping, credential-compromise branch, hunting |
| **SOC Lead** | Hard delete approval, P1 escalation, exec comms |
| **Identity Admin** | Session revocation, MFA method removal (if SOC lacks the role) |

**Pre-requisite access check — do this once, not during an incident:**
- Defender: `Security Reader` + `Search and Purge` (required for Explorer purge actions) + `Security Operator`
- Entra: `Security Operator` or delegated `Authentication Administrator` for MFA method removal
- Splunk: read on your email, proxy, DNS, and Entra sign-in indexes
- ServiceNow: `sn_si.analyst`

If you can't perform a step because of missing role, that's an escalation to SOC Lead, not a reason to skip it. Log the gap.

---

## 1. Intake — three paths in

### 1A. User report (Report Phishing button)
**Click path:** `security.microsoft.com` → **Actions & submissions** → **Submissions** → **User reported** tab → select the report.

Capture immediately: reporting user UPN, `NetworkMessageId`, sender address, sender display name, subject, received time (note UTC vs local).

### 1B. MDO alert
**Click path:** `security.microsoft.com` → **Incidents & alerts** → **Incidents** → open incident → **Evidence and Response** tab → **Email** entity.

Common alert names: *A potentially malicious URL click was detected*, *Email messages containing malicious URL removed after delivery*, *A user clicked through to a potentially malicious URL*, *Suspicious email sending patterns detected* (this last one means **your** user is sending phish — jump to §7).

### 1C. Splunk notable
**Click path:** Splunk ES → **Incident Review** → filter Security Domain = `Network` / `Access` → open notable → **Actions** → drill-down search.

**First action on any path: assign the notable/incident to yourself.** Unassigned tickets get double-worked or dropped at shift change.

---

## 2. Deduplication check (60 seconds — do not skip)

1. ServiceNow → **Security Incident** list → filter: `Short description CONTAINS <sender domain>` OR `Configuration item = <user>` in the last 7 days.
2. Defender → **Incidents** → search the sender address.
3. If an open SIR exists for the same campaign: add the new recipient to **Affected Users** on the existing SIR, add a work note, close your new intake as duplicate with the parent SIR number. **Do not open a second ticket for the same campaign.**

A "campaign" = same sender infrastructure OR same payload URL/hash OR same lure with different senders. Treat as one incident with many affected users.

---

## 3. Verify — is it actually malicious?

Pull the message. **Click path:** `security.microsoft.com` → **Email & collaboration** → **Explorer** → set date range → **Filter** → `Network Message ID` = `<id>` → click the subject → **Email entity page**.

The email entity page gives you, in one view: delivery action, delivery location, detection technologies, authentication results, URLs, attachments, and the timeline.

### 3.1 Authentication check
On the entity page, open the **Analysis** tab. Read:
- **SPF / DKIM / DMARC** — all three failing on a message claiming to be from a major brand is strong evidence.
- **Composite authentication (compauth)** — `fail` with reason `000`/`001` is spoofing.
- **Return-Path vs From** mismatch — classic.
- **Display name vs actual address** — `"IT Helpdesk" <random@gmail.com>` is the single most common pattern you'll see.

> Careful: DMARC pass does **not** mean legitimate. Attackers register their own domains and pass DMARC on them. Look-alike domain (`corp-hr.com` vs `corphr.com`) with perfect auth is very common. Check domain registration age — a domain registered 4 days ago is a strong signal.

### 3.2 Payload check
- **URLs:** open the **URLs** tab. Detonate in a sandbox or check reputation — do **not** browse to it from a corporate host. If you must look, use an isolated analysis VM or URL reputation services.
- **Attachments:** get the **SHA256** from the entity page. Check it in Defender (**Hunting** → search the hash) and against your threat intel. Do not open it.
- **QR codes in images** ("quishing"): MDO may not extract these. Decode the QR from the image in an analysis VM. This is now a very common bypass — if the email body is a single image with little text, suspect it.
- **No payload at all?** A plain-text email asking for a gift card, bank detail change, or "are you at your desk?" is **BEC**, not commodity phish. It's higher impact and MDO often doesn't flag it. Go to §7.

### 3.3 Classify
| Verdict | Meaning | Next |
|---|---|---|
| **Malicious** | Credential harvesting, malware, BEC, or fraud attempt | §4 |
| **Suspicious/unclear** | Can't confirm either way | Treat as malicious for containment, keep investigating. Erring toward containment on email is cheap. |
| **Spam** | Unsolicited bulk, not malicious | Close P4, add to spam filtering, tell the user it was reviewed |
| **Legitimate** | False report | Close as FP, thank the reporter (see template §10.3) |

**Never punish reporting.** If a user reports a legitimate email, the response is thanks, not correction. Under-reporting is far more expensive than over-reporting.

---

## 4. The decision tree

Everything from here depends on **what actually happened** to each recipient. Run the queries in §5 first, then follow the branch. Different recipients of the same campaign can be in different branches — handle each accordingly.

```
Malicious email confirmed
│
├─ BRANCH A: Was it delivered to any inbox?
│   │
│   ├─ NO — blocked / quarantined / filtered for all recipients
│   │   → Priority P4
│   │   → Verify quarantine (§6.1), add IoCs to block lists (§6.3),
│   │     submit to Microsoft (§6.6), close.
│   │   → NO user contact needed.
│   │
│   └─ YES — delivered to at least one inbox
│       │
│       └─ BRANCH B: Did anyone interact? (§5.2, §5.3)
│           │
│           ├─ NO interaction (no click, no attachment open, no reply)
│           │   → Priority P3
│           │   → Purge from all mailboxes (§6.1), block IoCs (§6.3),
│           │     notify recipients (§10.1), close.
│           │
│           ├─ CLICKED URL, no credential submission
│           │   → Priority P3
│           │   → Was the click BLOCKED by Safe Links? (check IsClickedThrough)
│           │   │   ├─ Blocked → treat as no-interaction, but confirm no
│           │   │   │   secondary payload landed (§5.4). Close P3.
│           │   │   └─ Clicked through → check the endpoint for drive-by
│           │   │       download (§5.4). If any file landed → BRANCH D.
│           │   → Purge, block, notify user, precautionary password reset
│           │     if you cannot rule out credential entry.
│           │
│           ├─ CREDENTIALS SUBMITTED (or cannot be ruled out)
│           │   → Priority P2 · P1 if the account is privileged
│           │   → GO TO BRANCH C — this is now an account compromise
│           │
│           └─ ATTACHMENT EXECUTED / payload ran
│               → Priority P2 · P1 if server, or if multiple hosts
│               → GO TO BRANCH D — this is now an endpoint compromise
│
├─ BRANCH C: Account compromise path
│   1. Revoke sessions + reset password IMMEDIATELY (§6.4) — before further investigation.
│      Token theft means the attacker doesn't need the password. Revocation is the control.
│   2. Check for post-compromise persistence (§5.5):
│      ├─ Inbox rules created?              → remove, and this confirms a live attacker
│      ├─ MFA method added?                 → remove it, force re-registration
│      ├─ OAuth app consented?              → revoke consent, check app permissions
│      ├─ Mailbox delegation added?         → remove
│      ├─ Email sent from the account?      → §7 (internal spread / BEC)
│      └─ Files shared externally?          → PB-10 data exfiltration
│   3. Any of the above present → escalate to P1, engage SOC Lead.
│      Persistence means it's a human operator, not automated harvesting.
│   4. Check whether the same source IP hit other accounts → PB-05.
│   5. Check if the account has admin roles → PB-09 review of all its actions.
│
└─ BRANCH D: Endpoint compromise path
    1. ISOLATE the device (§6.5) — full isolation.
    2. Collect investigation package BEFORE remediation (§6.5).
    3. Hand off to PB-02 (Malware) for eradication.
    4. Rotate credentials cached on that host, including the logged-on user.
    5. Hunt the hash + C2 across the fleet (§5.6). Multiple hosts → P1.
```

**Escalate to P1 immediately, regardless of branch, if:**
- The affected identity holds Global Admin, Exchange Admin, Domain Admin, or any tier-0 role
- The account is used for wire transfers, payroll, or vendor payment changes
- More than 10 users clicked through
- The payload is a known ransomware loader (Qakbot-family, IcedID, Pikabot, Latrodectus, or similar initial-access loaders)
- The email came *from* a trusted third party's real compromised account (supply chain — PB-17)

---

## 5. Query library

### 5.1 Full campaign scope
**Click path:** `security.microsoft.com` → **Hunting** → **Advanced hunting** → new query.

```kql
let lookback = 30d;
let badSender = "attacker@bad-domain.com";
let badDomain = "bad-domain.com";
EmailEvents
| where Timestamp > ago(lookback)
| where SenderFromAddress =~ badSender
    or SenderMailFromAddress has badDomain
    or SenderIPv4 == "203.0.113.10"
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderMailFromAddress, SenderIPv4,
          SenderDisplayName, RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation,
          ThreatTypes, DetectionMethods, AuthenticationDetails, EmailDirection
| order by Timestamp asc
```
Read `DeliveryLocation`: `Inbox/folder` = delivered (bad), `Quarantine` / `Junk folder` = filtered, `Deleted` = already remediated, `Failed`/`Dropped` = blocked.

**Widen the sender search** — attackers rotate. Also pivot on subject and on the URL:
```kql
EmailEvents
| where Timestamp > ago(30d)
| join kind=inner (EmailUrlInfo | where Url has "bad-domain.com" | project NetworkMessageId, Url) on NetworkMessageId
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, Url, DeliveryLocation
```

### 5.2 Who clicked
```kql
UrlClickEvents
| where Timestamp > ago(30d)
| where Url has "bad-domain.com"
| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, IPAddress, Workload, ThreatTypes
| order by Timestamp asc
```
- `ActionType == "ClickBlocked"` and `IsClickedThrough == 0` → Safe Links stopped them. Good.
- `IsClickedThrough == 1` → they clicked the "continue anyway" button. Treat as full exposure.
- **No row at all does not mean no click.** Safe Links only logs rewritten URLs. If the URL wasn't rewritten (plain-text mail, image-embedded link, QR code), check the proxy instead — §5.3.

### 5.3 Proxy corroboration (Splunk — catches what Safe Links misses)
```
index=proxy earliest=-30d
  (dest_host="bad-domain.com" OR url="*bad-domain.com*" OR dest_ip="203.0.113.10")
| stats count min(_time) as first_seen max(_time) as last_seen
        values(action) as actions values(url) as urls dc(url) as unique_urls
        by src_ip, user
| convert ctime(first_seen) ctime(last_seen)
| sort - count
```
Also check DNS, which catches clicks even when the proxy blocked the connection:
```
index=dns earliest=-30d query="*bad-domain.com*"
| stats count min(_time) as first_seen by src_ip, query, answer
| convert ctime(first_seen)
```

### 5.4 Did credentials get submitted? (the hard question)
There is no log that says "user typed password into attacker page." You infer it. Look for a successful sign-in from attacker-associated infrastructure shortly after the click:

```
index=azure_ad sourcetype="azure:aad:signin" earliest=-30d
  userPrincipalName="victim@corp.com"
| eval geo=coalesce('location.city',"unknown").", ".coalesce('location.countryOrRegion',"unknown")
| stats count min(_time) as first max(_time) as last
        values(appDisplayName) as apps values(status.errorCode) as codes
        by src_ip, geo, userAgent, authenticationRequirement, conditionalAccessStatus
| convert ctime(first) ctime(last)
| sort first
```

**Indicators that credentials were captured and used:**
| Signal | Why it matters |
|---|---|
| Successful sign-in from a new ASN/country within minutes–hours of the click | Direct evidence |
| Sign-in with `authenticationRequirement = singleFactorAuthentication` where the user normally does MFA | Token replay / AiTM session hijack |
| Same session/correlation ID from two different IPs | Stolen session cookie — password reset alone won't fix this, you must revoke |
| Sign-in from a hosting/VPN ASN (Digital Ocean, Hetzner, M247, residential-proxy ranges) | Attacker infrastructure |
| New device registered in Entra right after | Attacker establishing persistence |
| `errorCode 50158` (external security challenge) or unusual CA results | Adversary-in-the-middle framework behaviour |

**Modern phishing kits (Evilginx, Tycoon, Mamba) proxy the real login page and steal the session token — MFA does not stop them.** If the kit is AiTM-capable, assume compromise on any click-through and revoke sessions. Do not close on "but they have MFA."

**If you cannot rule it out:** treat as submitted. Precautionary reset + session revoke costs the user 5 minutes. The alternative costs weeks.

### 5.5 Post-compromise persistence sweep
```
index=o365 sourcetype="o365:management:activity" earliest=-30d
  UserId="victim@corp.com"
  Operation IN ("New-InboxRule","Set-InboxRule","UpdateInboxRules","Add-MailboxPermission",
                "Add-RecipientPermission","Set-Mailbox","Consent to application",
                "Add OAuth2PermissionGrant","Add service principal","Add member to role",
                "Update user","Add-MailboxFolderPermission","New-TransportRule")
| table _time, UserId, Operation, ObjectId, ClientIP, ClientIPAddress, Parameters
| sort _time
```
```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where AccountId has "victim" or AccountDisplayName has "victim"
| where ActionType has_any ("New-InboxRule","Set-InboxRule","Add-MailboxPermission",
        "Consent to application","Add OAuth2PermissionGrant","UpdateUser","Set-Mailbox")
| project Timestamp, ActionType, AccountDisplayName, IPAddress, ObjectName, RawEventData
```
**Rules to look for specifically:** anything forwarding to an external address, anything moving mail to RSS Feeds / Archive / Conversation History, anything deleting mail matching "invoice", "payment", "wire", "bank", "IT", "security". Attackers create these to hide replies from the victim.

Check MFA methods: `entra.microsoft.com` → **Users** → select user → **Authentication methods**. Look for a phone number or authenticator app registered during the compromise window.

### 5.6 Endpoint side (if an attachment ran)
```kql
let badHash = "<sha256>";
union DeviceFileEvents, DeviceProcessEvents, DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where SHA256 == badHash
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Events=count() by DeviceName, ActionType
| order by FirstSeen asc
```
```kql
// Office app spawning a process = macro/payload execution
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe")
| where FileName in~ ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe",
                      "rundll32.exe","regsvr32.exe","curl.exe","msiexec.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```
```kql
// Files written from Outlook temp / browser download during the incident window
DeviceFileEvents
| where Timestamp between (datetime(2026-07-30 09:00) .. datetime(2026-07-30 12:00))
| where FolderPath has_any ("Content.Outlook","INetCache","\\Downloads\\")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName
```

---

## 6. Containment — exact click paths

### 6.1 Purge the email from all mailboxes **[L1]**
1. `security.microsoft.com` → **Email & collaboration** → **Explorer**
2. Set the date range to cover the full campaign (from §5.1 `Timestamp` min/max, plus a day either side)
3. **Filter** → choose `Network Message ID`, `Sender address`, `Subject`, or `URL` → enter value → **Refresh**
4. Verify the result count matches your §5.1 scope. If it doesn't, your filter is too narrow — fix it before acting.
5. Select the header checkbox to select all → **Take action**
6. Choose the action:
   - **Move to Junk Email folder** — lowest impact, message still recoverable
   - **Move to Deleted Items** — standard choice for most phishing
   - **Soft delete** — removes from Deleted Items, still recoverable from Recoverable Items. **This is the default recommendation for confirmed malicious mail.**
   - **Hard delete** — unrecoverable. **Requires SOC Lead approval and a work note recording who approved.** Use only when Legal/Compliance requires it, and confirm no litigation hold conflict first.
7. Optionally tick **Submit to Microsoft for review** in the wizard
8. Add a tracking name → **Submit**
9. Monitor completion: **Actions & submissions** → **Action center** → **History** tab. Purges are asynchronous and can take 30+ minutes on large tenants. Do not report containment complete until the action shows finished.

**If the message is already in quarantine:** `Email & collaboration` → **Review** → **Quarantine** → select → **Delete**. Also check no user has requested release.

### 6.2 Check for release requests
`Email & collaboration` → **Review** → **Quarantine** → filter by the sender. If a user has requested release, **deny it** and note the requesting user — they were convinced by the lure and need follow-up.

### 6.3 Block the indicators **[L1]**

**Email indicators** — `security.microsoft.com` → **Email & collaboration** → **Policies & rules** → **Threat policies** → **Tenant Allow/Block Lists**:
- **Domains & addresses** tab → **Block** → add sender domain (block the domain, not just the address — they rotate the local part) → set expiry (90 days, or Never expires for confirmed-malicious infrastructure)
- **URLs** tab → **Block** → add the payload URL and its domain with wildcard
- **Files** tab → **Block** → add the attachment SHA256

**Endpoint indicators** — `security.microsoft.com` → **Settings** → **Endpoints** → **Indicators**:
- **File hashes** tab → **Add item** → SHA256 → Action: **Block and remediate** → scope: All devices → generate alert: Yes
- **IP addresses / URLs** tab → **Add item** → the C2 or phishing domain → Action: **Block and remediate**

**Network** — block the domain and IP at proxy/firewall/DNS. If you have the Splunk Adaptive Response integration for your firewall, you can push this from the notable: Incident Review → notable → **Actions** → select the block action. Otherwise raise it to Network Ops as a P2 task and track it on the SIR.

**Then create a detection for future hits:**
```
index=proxy OR index=dns OR index=firewall dest_host="bad-domain.com"
```
Save as an alert with a 15-minute schedule so you catch late clickers.

### 6.4 Contain the identity (BRANCH C) **[L2]**
Order matters. Do 1 and 2 within the same minute.

1. **Revoke sessions:** `entra.microsoft.com` → **Users** → select user → **Revoke sessions**. This invalidates refresh tokens. *Do this even if you're resetting the password* — a password reset alone does not kill a stolen session token in all cases.
2. **Reset password:** same page → **Reset password**. Deliver the temporary password **out-of-band** (phone call to a known number, or in person). Never email it — the mailbox may be attacker-controlled.
3. **Review and remove attacker MFA methods:** → **Authentication methods** → delete anything registered during the compromise window → then require the user to re-register.
4. **Block sign-in** if you need time before the user is reachable: → **Overview** → **Block sign-in** toggle. Set a reminder to unblock; a blocked exec at month-end generates its own incident.
5. **Contain user in Defender XDR** (limits lateral movement from that identity): incident page → user entity → **Contain user**.
6. **Remove malicious inbox rules:** Exchange admin center → recipient → mailbox rules; or PowerShell: `Get-InboxRule -Mailbox victim@corp.com | Format-List` then remove by identity. Screenshot the rule before deleting it — it's evidence of attacker intent.
7. **Revoke OAuth consents:** `entra.microsoft.com` → **Enterprise applications** → find the app → **Permissions** → review → delete the app or revoke consent. Also check **Users and groups** to see who else consented.
8. **Block the attacker IP:** Entra → **Conditional Access** → **Named locations** → add as a blocked location, or handle at the edge.

### 6.5 Contain the endpoint (BRANCH D) **[L2]**
1. `security.microsoft.com` → **Assets** → **Devices** → select device → **Collect investigation package** — **do this first**, before isolation changes state and before remediation destroys artifacts. Download from **Action center** → **History** when ready.
2. Same page → **Isolate device** → choose **Full** (Selective only if the user genuinely needs Teams/Outlook contact and you accept the risk). Provide a comment — it appears in the audit log.
3. **Run antivirus scan** → Full.
4. If you need hands-on: **Initiate Live Response** → useful commands: `processes`, `connections`, `getfile <path>`, `run <script>`, `remediate file <path>`, `persistence` (via community scripts in the library).
5. Hand off to **PB-02** for eradication and the reimage decision.

### 6.6 Submit to Microsoft
`security.microsoft.com` → **Actions & submissions** → **Submissions** → **Emails** tab → **Submit to Microsoft for analysis** → paste the Network Message ID → select "should have been blocked" → submit. This improves tenant-wide detection and is worth the 30 seconds.

---

## 7. Special case: your own user is now sending phish (internal BEC spread)

This is the highest-urgency variant because it abuses trust and bypasses your perimeter controls entirely.

**Detect:**
```kql
EmailEvents
| where Timestamp > ago(7d)
| where SenderFromAddress =~ "victim@corp.com" and EmailDirection == "Outbound" or EmailDirection == "Intra-org"
| summarize Recipients=dcount(RecipientEmailAddress), RecipientList=make_set(RecipientEmailAddress, 100),
            Subjects=make_set(Subject, 10) by bin(Timestamp, 1h)
| where Recipients > 20
```
**Response:**
1. Full BRANCH C containment on the sending account, immediately.
2. Purge the outbound messages from all **internal** recipients (§6.1 — Explorer covers intra-org mail).
3. For **external** recipients: you have notified-party obligations. Escalate to SOC Lead + Legal + Comms. Someone must contact those organizations — usually via your account managers, with a Legal-approved message. Track the recipient list as evidence.
4. Check for **thread hijacking** — attackers reply inside existing legitimate threads, which is extremely effective. Search the account's Sent Items for replies during the compromise window.
5. Check for **payment/vendor detail change requests** in the sent mail. If any exist, alert Finance *by phone* immediately and freeze the relevant payments. This is where actual money is lost.
6. Escalate to **P1**. Add Finance and Legal as watchers on the SIR.

---

## 8. Verification before closure

Do not close until every box is ticked and evidenced in a work note:

- [ ] All malicious messages removed — re-run §5.1 and confirm zero rows with `DeliveryLocation == "Inbox/folder"`
- [ ] Action center shows all purge actions **completed**, not pending
- [ ] Quarantine checked; no pending release requests
- [ ] All IoCs blocked in: Tenant Allow/Block List, Defender Indicators, proxy, DNS, firewall
- [ ] Every clicker identified and their account status determined (compromised / not compromised, with evidence)
- [ ] For compromised accounts: sessions revoked, password reset, MFA re-registered, rules/consents/delegations cleaned, verified no re-authentication from attacker infrastructure in the following 24h
- [ ] For affected endpoints: PB-02 closed out
- [ ] Detection alert created for future hits on the IoCs
- [ ] Submitted to Microsoft
- [ ] Users notified (§10)
- [ ] IoCs shared to your threat intel platform / ISAC if you participate
- [ ] Monitoring extended 7 days on affected identities and hosts

**Post-closure watch query** (schedule for 7 days):
```
index=azure_ad sourcetype="azure:aad:signin" userPrincipalName="victim@corp.com"
| search NOT src_ip IN (<known good corporate ranges>)
| table _time, src_ip, location.countryOrRegion, appDisplayName, status.errorCode
```

---

## 9. False positive catalogue

| Pattern | How to confirm it's benign | Action |
|---|---|---|
| **Phishing simulation** | Cross-reference the sender/IP against your awareness platform's allowlist. Every simulation sender should be in a lookup you maintain. | Close as Benign True Positive. **Praise the reporter.** Do not tell them it was a test unless your awareness program says to. |
| **Red team / pentest** | Check the active engagement register and deconfliction contact | Contact the engagement lead before containing. If in doubt, contain — that's the correct default and the red team should expect it. |
| **Marketing bulk mail** | Valid DKIM on a real brand domain, unsubscribe header present, list-unsubscribe compliant | Close P4, add to spam controls if the user wants |
| **Legitimate DocuSign / Adobe / Xero notification** | URL resolves to the real vendor domain (check for look-alikes: `docusign.net` real vs `docusign-verify.com` fake) | Close as FP, educate the user on how to verify |
| **Internal newsletter with tracking links** | Sender is internal, links go to your own tracking domain | Close FP; consider allowlisting the tracking domain |
| **Recruiter / cold sales outreach** | No payload, no credential request, real LinkedIn presence | Close P4 |
| **User forwarded their own suspicious mail as an attachment** | The "malicious" sender is your own user | Analyse the nested message, not the wrapper |

**Every FP closure must end with either a tuning action or a documented reason not to tune.** Maintain these lookups so this table is enforceable:
- `phishing_simulation_senders.csv`
- `approved_bulk_senders.csv`
- `redteam_engagement_infrastructure.csv`

---

## 10. Communication templates

### 10.1 Recipient notification — no interaction detected
> **Subject: Security notice — malicious email removed from your mailbox**
>
> Hi [Name],
>
> We identified a malicious email sent to you on [date] with the subject "[subject]" and have removed it from your mailbox. Our records show you did not interact with it, so no action is needed on your part.
>
> If you did click a link or open an attachment in that message — even if you're unsure — please reply or call us on [number]. There's no problem if you did; we just need to know so we can check your account. It's genuinely better for us to hear about it than not.
>
> Thanks,
> [SOC / Security Team] · Ref: [SIR number]

### 10.2 Compromised user notification — call, don't email
Call first. Their mailbox may be attacker-controlled and email may be intercepted or auto-deleted.

> Script: "Hi [Name], this is [Name] from the security team. We've found that your account was accessed by someone else after a phishing email on [date]. I've already reset your password and signed out all sessions — that's why you'll be locked out right now. I need to give you a temporary password over the phone and walk you through setting up your authenticator again. This takes about five minutes. To be clear, you haven't done anything wrong — these emails are designed to be convincing. A couple of questions so I can check the full picture: did you enter your password anywhere unusual, approve any sign-in prompts you didn't start, or notice any missing emails?"

Then confirm in writing to their manager and the user once access is restored.

### 10.3 Reporter thank-you (including for false positives)
> Thanks for reporting this — we've reviewed it. [It was malicious and we've removed it from everyone's mailbox. / It turned out to be legitimate, but reporting it was exactly the right call.] Please keep sending anything that looks off; we'd much rather check a hundred safe emails than miss one real attack.

### 10.4 P1 exec brief structure (BEC / wide campaign)
Five bullets, no jargon, one page maximum:
1. **What happened** — one sentence
2. **Current status** — contained / in progress, and what specifically is contained
3. **Impact** — accounts affected, data involved, money at risk, systems down
4. **What we're doing next** — with owners and times
5. **What we need from you** — decisions required, nothing else

Update cadence: every 60 minutes for P1 until contained, then at close.

---

## 11. ServiceNow SIR field guide

| Field | Value |
|---|---|
| **Category** | Phishing |
| **Subcategory** | Credential Harvesting / Malware Delivery / BEC / Spam |
| **Impact** | 1 if privileged account or finance role; 2 if credentials compromised; 3 otherwise |
| **Urgency** | 1 if active attacker session; 2 if credentials submitted; 3 if delivered only |
| **Assignment group** | SOC L1 (escalate to SOC L2 on BRANCH C/D) |
| **Affected User(s)** | Every recipient who received it in-inbox — populate the related list, not the description |
| **Affected CI(s)** | Any device from BRANCH D |
| **Attachments** | Original .eml/.msg, email entity page screenshot, Advanced Hunting CSV export, Action center completion screenshot, investigation package (if BRANCH D) |
| **Work notes** | Every action with UTC timestamp, analyst name, tool used |
| **Resolution code** | True Positive – Contained / False Positive / Benign True Positive |
| **Close notes** | Initial access vector, scope (X delivered / Y clicked / Z compromised), containment actions, root cause, follow-up items with ticket numbers |

**State progression:** Draft → Analysis (§3–5) → Contain (§6) → Eradicate (§6.4/6.5) → Recover (§8) → Review (P1/P2 only) → Closed.

**Related records to raise, not bury in close notes:**
- Repeat clicker → task to awareness team
- Detection gap → Problem record for detection engineering
- Missing control (e.g. no MFA on that account, Safe Links not covering a mail flow) → Change request
- Vendor account compromised → PB-17 SIR

---

## 12. Timing targets

| Milestone | P1 | P2 | P3 |
|---|---|---|---|
| Acknowledged and assigned | 15 min | 30 min | 4 hr |
| Verdict reached (§3) | 30 min | 1 hr | 8 hr |
| Email purged | 1 hr | 2 hr | 24 hr |
| Identity contained (BRANCH C) | 30 min | 1 hr | n/a |
| Endpoint isolated (BRANCH D) | 30 min | 1 hr | n/a |
| Full scope established | 2 hr | 4 hr | 48 hr |
| Closed | 24 hr + PIR | 72 hr | 5 days |

---

## 13. Known limitations of this runbook
Stated plainly so nobody is surprised at 3am:

- **Safe Links click data is incomplete.** Plain-text links, image-embedded links, QR codes, and links in attachments may not be rewritten or logged. Proxy and DNS logs are your backstop — if you don't have them in Splunk, you have a real visibility gap and should raise it.
- **You cannot definitively prove credentials were not entered.** The tree handles this by defaulting to containment. Resist pressure to close on "probably fine."
- **MFA is not a containment control against AiTM kits.** Session revocation is.
- **BEC with no payload often has no alert.** User reporting is your primary detection for this. That makes §10.3 (never discouraging reports) an operational control, not a courtesy.
- **Purge is asynchronous and can partially fail.** Always verify in Action center rather than assuming.
- **Explorer's retention window** limits historical hunting. Check what your licence gives you (typically 30 days for Explorer, 30 days for Advanced Hunting) and keep longer retention in Splunk for anything you might need at month 4.
