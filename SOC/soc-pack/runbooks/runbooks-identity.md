# IDENTITY RUNBOOKS
### PB-04 Account Compromise · PB-05 Brute Force & Password Spray · PB-09 Privilege Escalation

**Tools:** Entra ID (`entra.microsoft.com`) · Defender XDR + Defender for Identity · Splunk Cloud ES · ServiceNow SecOps
**Primary script:** `scripts/Invoke-IdentityContainment.ps1` · `scripts/Get-MailboxCompromiseEvidence.ps1`

---
---

# PB-04 · Compromised Account / Credential Compromise

**Default priority:** P2 · **P1** if the account holds any privileged role, has finance/payment authority, or an attacker session is currently active.

**Detection sources:** Entra ID Protection risk detections, MDI alerts, Splunk correlation (`Credential Submission Following Malicious URL Click`, `Successful Authentication After Brute Force`, `MFA Push Bombing`), user report ("I'm getting MFA prompts I didn't ask for"), inbound notification from a third party.

---

## Step 1 — Contain first, investigate second

This is the one identity runbook where you act before you finish analysing. If you have credible evidence of compromise, revoke now. A wrong revocation costs a user ten minutes. A delayed revocation costs weeks.

```powershell
# Immediate containment — revoke sessions and block sign-in
.\Invoke-IdentityContainment.ps1 -UserPrincipalName victim@corp.com `
    -RevokeSessions -BlockSignIn -CollectEvidence -Ticket SIR0012345
```

**Manual click path:** `entra.microsoft.com` → **Users** → select user → **Revoke sessions**, then **Block sign-in** (Overview tab).

**Why revoke and not just reset the password:** modern adversary-in-the-middle phishing kits (Evilginx, Tycoon, Mamba, EvilProxy) steal the **session token**, not the password. The attacker never needs to authenticate again. A password reset alone leaves their session alive. Revocation invalidates refresh tokens; that is the control that actually works.

> Access-token lifetime is typically around an hour by default, so there can be a short residual window after revocation. Continuous Access Evaluation shortens this for supported workloads. Don't treat revocation as instant for every app — verify with Q4.6 that authentication from attacker infrastructure has actually stopped.

---

## Step 2 — Decision tree

```
Suspected account compromise
│
├─ CONFIRM: is there a successful sign-in you can't attribute to the user? (Q4.1)
│   ├─ NO  → possibly failed attempt only → PB-05. Still reset if credentials were phished.
│   └─ YES → confirmed. Continue.
│
├─ CONTAIN (Step 1) — before anything below.
│
├─ SCOPE: what did the attacker do? Run ALL of Q4.2–Q4.5. Do not stop at the first finding.
│   │
│   ├─ Inbox rule created (forward / delete / move-to-obscure-folder)
│   │   → HUMAN OPERATOR CONFIRMED. Escalate P2→P1.
│   │     Automated credential harvesting doesn't create rules. Someone read the mailbox.
│   │     Screenshot the rule before deleting — it shows intent (keywords like "invoice",
│   │     "payment", "wire", "bank", "security", "IT" tell you the objective).
│   │
│   ├─ MFA method registered by attacker
│   │   → P1. They intended persistent access. Remove the method, force re-registration,
│   │     and check whether any Conditional Access policy was thereby satisfied.
│   │
│   ├─ OAuth application consented
│   │   → P1. Illicit consent grant = persistence that survives password reset AND
│   │     session revocation. You MUST revoke the grant or you are not contained.
│   │     Check the app's granted scopes — Mail.ReadWrite / Files.ReadWrite.All /
│   │     offline_access are the ones that matter.
│   │
│   ├─ Mailbox delegation / folder permission added
│   │   → P1. Same reasoning: survives credential reset.
│   │
│   ├─ Mail sent from the account
│   │   → PB-01 §7 (internal phishing spread). Check specifically for payment-detail
│   │     change requests → phone Finance immediately, freeze affected payments.
│   │
│   ├─ Files downloaded / shared externally (Q4.5)
│   │   → PB-10. Data breach assessment. Legal.
│   │
│   ├─ Privileged role assigned to this or another account
│   │   → PB-09, P1. Domain/tenant compromise path.
│   │
│   ├─ New device registered / Entra joined
│   │   → P1. Device-based persistence and potential CA bypass. Remove the device object.
│   │
│   └─ Nothing found beyond the sign-in
│       → P2. Still complete full containment. "We found nothing" after a 30-day
│         search is a finding; "we didn't look" is not.
│
├─ LATERAL: did the same source IP touch other accounts? (Q4.7)
│   └─ YES → multi-account compromise. Escalate P1, repeat this runbook per account.
│
├─ PRIVILEGE: does the account hold admin roles?
│   └─ YES → P1. Review every action taken under that identity for the full window.
│            Assume anything it could reach is compromised.
│
└─ ON-PREM: is this a hybrid identity? (Q4.8)
    └─ YES → check for on-prem compromise too. A synced account compromised in the
             cloud may also mean the on-prem account or Azure AD Connect is affected.
```

---

## Step 3 — Query library

**Q4.1 — Sign-in baseline vs anomaly**
```
index=azure_ad sourcetype="azure:aad:signin" earliest=-60d
  userPrincipalName="victim@corp.com"
| rename ipAddress as src_ip
| lookup corporate_ip_ranges.csv cidr as src_ip OUTPUT description as corp_site
| eval src_type=if(isnull(corp_site),"external","corporate")
| eval outcome=if('status.errorCode'==0,"success","failure")
| stats count min(_time) as firstTime max(_time) as lastTime
        values(appDisplayName) as apps values(userAgent) as agents
        by src_ip, src_type, "location.countryOrRegion", "location.city", outcome,
           authenticationRequirement, conditionalAccessStatus
| convert ctime(firstTime) ctime(lastTime)
| sort firstTime
```
Read it as a baseline: 55 days of the same three IPs, then something new. The new thing is your incident.

**Attacker-infrastructure indicators in this output:**
| Signal | Interpretation |
|---|---|
| `authenticationRequirement = singleFactorAuthentication` on a user who always does MFA | Token replay / AiTM session hijack |
| Hosting-provider ASN (DigitalOcean, Hetzner, M247, Choopa, residential proxy pools) | Attacker infrastructure |
| `userAgent` mismatch with the user's known devices | Different client |
| Two IPs sharing one correlation/session ID | Stolen session cookie — revocation is mandatory, reset alone will not fix it |
| `conditionalAccessStatus = notApplied` where it normally applies | CA gap or a bypassed policy — raise as a finding |
| Legacy auth protocols (IMAP/POP/SMTP AUTH/EWS basic) | Legacy auth is a common bypass. If still enabled, that's a Change request. |

**Q4.2 — Post-compromise operations (the most important query in this runbook)**
```
index=o365 sourcetype="o365:management:activity" earliest=-30d
  UserId="victim@corp.com"
  Operation IN ("New-InboxRule","Set-InboxRule","UpdateInboxRules","Enable-InboxRule",
                "Add-MailboxPermission","Add-RecipientPermission","Add-MailboxFolderPermission",
                "Set-Mailbox","New-TransportRule","Set-TransportRule",
                "Consent to application","Add OAuth2PermissionGrant","Add service principal",
                "Add member to role","Add app role assignment grant to user",
                "Update user","Add owner to application","Add delegated permission grant",
                "UserLoggedIn","MailItemsAccessed","Send","SendAs","SendOnBehalf",
                "New-MailboxExportRequest","Set-CASMailbox")
| table _time, UserId, Operation, ClientIP, ObjectId, Parameters, ResultStatus
| sort _time
```
```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where AccountUpn =~ "victim@corp.com" or RawEventData has "victim@corp.com"
| where ActionType has_any ("InboxRule","MailboxPermission","Consent","OAuth2PermissionGrant",
        "service principal","Add member to role","Set-Mailbox","Set-CASMailbox","MailItemsAccessed",
        "New-MailboxExportRequest","AnonymousLinkCreated","SharingInvitationCreated")
| project Timestamp, ActionType, AccountUpn, IPAddress, ObjectName, ActivityObjects, RawEventData
| order by Timestamp asc
```

**Q4.3 — Inbox rules and forwarding (PowerShell — the authoritative source)**
```powershell
Connect-ExchangeOnline
$u = 'victim@corp.com'

# Rules — the full object, not a summary. Look at every field.
Get-InboxRule -Mailbox $u | Format-List Name,Enabled,Priority,Description,
    ForwardTo,ForwardAsAttachmentTo,RedirectTo,DeleteMessage,MoveToFolder,
    MarkAsRead,From,SubjectContainsWords,BodyContainsWords,StopProcessingRules

# Mailbox-level forwarding (separate from rules — check both)
Get-Mailbox $u | Select-Object ForwardingAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward

# Protocol settings (attackers re-enable legacy protocols for persistence)
Get-CASMailbox $u | Select-Object ImapEnabled,PopEnabled,SmtpClientAuthenticationDisabled,
    EwsEnabled,ActiveSyncEnabled,OWAEnabled

# Delegation
Get-MailboxPermission -Identity $u | Where-Object {$_.User -notlike 'NT AUTHORITY*' -and -not $_.IsInherited}
Get-RecipientPermission -Identity $u | Where-Object {$_.Trustee -notlike 'NT AUTHORITY*'}
Get-MailboxFolderPermission -Identity "${u}:\Inbox" -ErrorAction SilentlyContinue

# Export requests (bulk mailbox theft)
Get-MailboxExportRequest -Mailbox $u -ErrorAction SilentlyContinue
```
`scripts/Get-MailboxCompromiseEvidence.ps1` runs all of this and writes a timestamped evidence file for the SIR.

**Rules designed to hide activity — look for these specifically:**
- Forward or redirect to any external address
- `DeleteMessage = True` combined with subject keywords
- Move to `RSS Feeds`, `RSS Subscriptions`, `Conversation History`, `Archive`, `Junk`, or a rule with a blank/single-character name
- `StopProcessingRules = True` (hides the rule's effect from later rules)

**Q4.4 — OAuth grants and registered devices**
```powershell
Connect-MgGraph -Scopes "Directory.Read.All","AuditLog.Read.All","Application.Read.All"
$user = Get-MgUser -UserId 'victim@corp.com'

# Delegated grants made by this user
Get-MgOauth2PermissionGrant -Filter "principalId eq '$($user.Id)'" |
    Select-Object ClientId,ResourceId,Scope,ConsentType

# Resolve the app names and look at the scopes
Get-MgOauth2PermissionGrant -Filter "principalId eq '$($user.Id)'" | ForEach-Object {
    $sp = Get-MgServicePrincipal -ServicePrincipalId $_.ClientId
    [pscustomobject]@{App=$sp.DisplayName; Publisher=$sp.PublisherName;
                      AppId=$sp.AppId; Scopes=$_.Scope}
}

# MFA / auth methods — anything registered during the compromise window is the attacker's
Get-MgUserAuthenticationMethod -UserId $user.Id |
    Select-Object Id,AdditionalProperties

# Devices registered to the user
Get-MgUserRegisteredDevice -UserId $user.Id |
    Select-Object Id,@{n='Name';e={$_.AdditionalProperties.displayName}},
                     @{n='Created';e={$_.AdditionalProperties.createdDateTime}}
```
**Scopes that mean full mailbox/file access:** `Mail.Read`, `Mail.ReadWrite`, `Mail.Send`, `Files.Read.All`, `Files.ReadWrite.All`, `offline_access` (persistent refresh token), `User.Read.All`, `Directory.ReadWrite.All`. An unfamiliar app with `Mail.ReadWrite` + `offline_access` is an exfiltration channel that survives every credential action you take.

**Q4.5 — File access and external sharing**
```
index=o365 sourcetype="o365:management:activity" earliest=-30d
  UserId="victim@corp.com"
  Operation IN ("FileDownloaded","FileSyncDownloadedFull","FileAccessed","FilePreviewed",
                "AnonymousLinkCreated","AnonymousLinkUsed","SharingInvitationCreated",
                "AddedToSecureLink","SecureLinkCreated","CompanyLinkCreated","FileUploaded")
| stats count dc(SourceFileName) as unique_files values(Operation) as ops
        values(SiteUrl) as sites min(_time) as firstTime max(_time) as lastTime
        by UserId, ClientIP
| convert ctime(firstTime) ctime(lastTime)
| sort - unique_files
```
More than a few hundred unique files downloaded from a non-corporate IP → PB-10, data breach assessment.

**Q4.6 — Containment verification (run 1h, 4h, 24h after containment)**
```
index=azure_ad sourcetype="azure:aad:signin" earliest=-24h
  userPrincipalName="victim@corp.com" ipAddress IN ("<attacker IPs>")
| table _time, ipAddress, appDisplayName, status.errorCode, status.failureReason, authenticationRequirement
| sort _time
```
Expect failures only. **Continued successes after revocation means you missed a persistence mechanism** — go back to Q4.4 (OAuth grant, app password, or a registered device).

**Q4.7 — Same attacker, other victims**
```
index=azure_ad sourcetype="azure:aad:signin" earliest=-30d
  ipAddress IN ("<attacker IP>", "<attacker IP 2>")
| eval outcome=if('status.errorCode'==0,"SUCCESS","failure")
| stats count by userPrincipalName, outcome, appDisplayName
| sort - outcome, - count
```
Also pivot on the ASN, not just the IP — attackers rotate within a hosting provider:
```
index=azure_ad sourcetype="azure:aad:signin" earliest=-30d
  "location.countryOrRegion"="<attacker country>" "status.errorCode"=0
| lookup corporate_ip_ranges.csv cidr as ipAddress OUTPUT description as corp_site
| where isnull(corp_site)
| stats dc(userPrincipalName) as users values(userPrincipalName) as user_list count by ipAddress
| sort - users
```

**Q4.8 — Hybrid identity / on-prem correlation**
```kql
IdentityLogonEvents
| where Timestamp > ago(30d) and AccountUpn =~ "victim@corp.com"
| summarize Logons=count(), Devices=make_set(DeviceName,20), IPs=make_set(IPAddress,20)
    by LogonType, Application, ActionType
| order by Logons desc
```
```kql
IdentityDirectoryEvents
| where Timestamp > ago(30d)
| where AccountUpn =~ "victim@corp.com" or TargetAccountUpn =~ "victim@corp.com"
| project Timestamp, ActionType, AccountUpn, TargetAccountUpn, DeviceName, AdditionalFields
```

---

## Step 4 — Containment options (full sequence)

| # | Action | Click path | Script flag | Notes |
|---|---|---|---|---|
| 1 | **Revoke sessions** | Users → user → Revoke sessions | `-RevokeSessions` | Always. First. |
| 2 | **Block sign-in** | Users → user → Overview → Block sign-in | `-BlockSignIn` | Buys time before you can reach the user. **Set a reminder to unblock** — a blocked exec at month-end creates its own incident. |
| 3 | **Reset password** | Users → user → Reset password | `-ResetPassword` | Deliver **out-of-band** (phone to a known number). Never email — the mailbox may be attacker-read. |
| 4 | **Remove attacker MFA methods** | Users → user → Authentication methods | manual | Delete anything registered in the compromise window, then require re-registration. |
| 5 | **Contain user in Defender XDR** | Incident → user entity → Contain user | manual | Limits lateral movement from the identity across MDE-managed devices. |
| 6 | **Delete malicious inbox rules** | EAC, or `Remove-InboxRule` | `-RemoveInboxRules` | **Screenshot first.** Evidence of intent. |
| 7 | **Revoke OAuth consent** | Enterprise applications → app → Permissions | manual | Non-negotiable if a grant exists. Consider deleting the service principal entirely. |
| 8 | **Remove delegations** | `Remove-MailboxPermission` | manual | |
| 9 | **Reset forwarding** | `Set-Mailbox -ForwardingSmtpAddress $null` | `-ClearForwarding` | Check both rule-level and mailbox-level. |
| 10 | **Remove attacker-registered devices** | Devices → filter by owner → Delete | manual | |
| 11 | **Block attacker IPs** | Conditional Access → Named locations (blocked) | manual | Or at the edge. Prefer ASN-level if the attacker is rotating. |
| 12 | **Revoke app passwords / disable legacy auth** | `Set-CASMailbox` | manual | Legacy protocols bypass CA and MFA. |

**Reset-only vs full containment — choosing:**
| Situation | Minimum action |
|---|---|
| Credentials phished, no successful attacker sign-in found | Revoke + reset. No block needed. |
| Successful attacker sign-in, no persistence found | Revoke + reset + MFA re-registration |
| Any persistence found (rule/OAuth/MFA/device/delegation) | Everything in the table, P1, plus 30-day monitoring |
| Privileged account | Everything, plus full audit of all actions taken under the identity |

---

## Step 5 — Recovery
1. Re-enable sign-in; confirm the user re-enrols their own MFA (watch them do it, or verify the method afterwards).
2. Phone the user (script in `runbook-PB01-phishing.md` §10.2) — do not lead with blame.
3. Ask them directly: did you enter your password anywhere unusual, approve a prompt you didn't start, or notice missing emails? Their answer often finds things your queries didn't.
4. Check password reuse: if the same password was used for VPN, local admin, SaaS, or a personal account, those need rotating too.
5. 30-day enhanced monitoring on the identity (Q4.6 scheduled daily).

## Step 6 — Verification checklist
- [ ] Sessions revoked; verified no further successful auth from attacker infrastructure (Q4.6 at 1h/4h/24h)
- [ ] Password reset and delivered out-of-band
- [ ] Attacker MFA methods removed; user re-enrolled
- [ ] All four persistence classes checked: inbox rules, OAuth grants, delegations, devices
- [ ] Mailbox-level *and* rule-level forwarding both cleared
- [ ] Legacy auth protocols reviewed on the mailbox
- [ ] Attacker IP/ASN pivoted for other victims (Q4.7)
- [ ] If privileged: full action audit completed
- [ ] Data access assessed (Q4.5); Legal engaged if applicable
- [ ] Hybrid identity checked on-prem (Q4.8)
- [ ] 30-day monitoring scheduled

## Step 7 — False positives
| Pattern | Confirm |
|---|---|
| Travel | Ask the user. Corroborate with a booking or a manager, not just "yes" over the compromised channel. |
| Corporate VPN egressing in another country | Your own VPN IP list |
| New MFA enrolment after phone replacement | User confirms, and the enrolment came from a corporate IP |
| Shared/service account used from many places | Real FP, but a genuine control gap — raise it |
| Security tooling authenticating as the user | Known scanner/agent IPs |
| Legitimate third-party app consent | App is in your approved app list |

## Step 8 — ServiceNow
Category `Account Compromise` · Subcategory `Credential Phishing / Token Theft / Brute Force / Insider`
Impact 1 if privileged or finance-authorised. Urgency 1 if an attacker session is live.
Attach: sign-in log export, inbox rule screenshots, OAuth grant list, evidence file from `Get-MailboxCompromiseEvidence.ps1`.
Close notes must state: initial access vector, attacker dwell time, every persistence mechanism found and removed, data accessed, and verification evidence that containment held.

---
---

# PB-05 · Brute Force / Password Spray / MFA Fatigue

**Default priority:** P3 for attempts · **P2 on any success** (then run PB-04) · **P1** if the successful account is privileged

## Step 1 — Decision tree
```
High-volume authentication failures
│
├─ Is the source INTERNAL? (check against corporate_ip_ranges.csv)
│   ├─ YES → This is not an external attacker. A compromised host or a
│   │        misconfigured service account is spraying internally.
│   │        → P2. Identify the process on the host (Q5.5). Run PB-02 / PB-08.
│   │        This is a much more serious finding than external spray.
│   └─ NO  → external, continue
│
├─ Pattern classification (Q5.1, Q5.2)
│   ├─ Many accounts, few passwords each, low rate  → PASSWORD SPRAY (evades lockout by design)
│   ├─ One account, many passwords                  → TARGETED BRUTE FORCE. Why that account?
│   │                                                  Check if it's privileged or public-facing.
│   ├─ Credential-stuffing pattern (valid usernames,
│   │  one attempt each, high volume)               → breached credential list in use.
│   │                                                  Check your accounts against known
│   │                                                  breach exposure.
│   └─ Errors that are NOT wrong-password
│      (e.g. "user not found")                      → enumeration, not brute force.
│                                                     Still worth blocking; different fix.
│
├─ ANY SUCCESS? (Q5.3) — this is the only question that changes priority
│   ├─ NO  → P3. Block source, close, raise MFA-coverage gaps as findings.
│   └─ YES → P2/P1. GO TO PB-04 for that account immediately. The spray is now secondary.
│
├─ MFA outcome on any success (Q5.4)
│   ├─ MFA blocked it → control worked. Note which accounts were exposed
│   │                    (correct password, MFA saved them) — those users need
│   │                    a password reset even though the attack failed.
│   ├─ MFA not required → CONTROL GAP. P2. This account had no MFA.
│   │                     Raise a Change to close the gap tenant-wide.
│   └─ MFA fatigue approval → PB-04, P1. See Q5.6.
│
└─ Which accounts were targeted?
    → If the target list looks curated (all Finance, all admins, all C-suite),
      the attacker did reconnaissance. That's a more capable actor and the
      target list itself is intelligence. Preserve it.
```

## Step 2 — Queries

**Q5.1 — Spray detection**
```
index=azure_ad sourcetype="azure:aad:signin" earliest=-24h
  "status.errorCode" IN (50126, 50053, 50055, 50056, 50076, 50079)
| rename ipAddress as src_ip, userPrincipalName as user
| iplocation src_ip
| stats dc(user) as unique_users count as attempts
        values(user) as targeted values("status.errorCode") as codes
        values(appDisplayName) as apps values(Country) as country
        min(_time) as firstTime max(_time) as lastTime
        by src_ip
| where unique_users >= 10
| eval duration_hrs=round((lastTime-firstTime)/3600,1),
       rate=round(attempts/(duration_hrs+0.01),1)
| convert ctime(firstTime) ctime(lastTime)
| sort - unique_users
```
**Entra error code reference:**
| Code | Meaning | Significance |
|---|---|---|
| 50126 | Invalid username or password | Standard brute force / spray |
| 50053 | Account locked (smart lockout) | Your lockout is working |
| 50055 | Password expired | Valid password found on a stale account |
| 50056 | Invalid or null password | |
| 50076 / 50079 | MFA required / MFA enrolment required | **Password was correct.** MFA saved you. Reset that password. |
| 50158 | External security challenge not satisfied | Often seen with AiTM frameworks |
| 500121 | MFA challenge failed/denied/timed out | MFA fatigue signal |
| 50034 | User not found | Enumeration, not brute force |
| 53003 | Blocked by Conditional Access | CA working |

> **Codes 50076/50079 are the most under-triaged signal in this playbook.** They mean the attacker had the correct password and only MFA stopped them. Those accounts need a password reset even though the attack "failed."

**Q5.2 — On-prem brute force**
```
index=wineventlog EventCode=4625 earliest=-24h
| stats count dc(Account_Name) as accounts values(Account_Name) as targeted
        values(Failure_Reason) as reasons values(Logon_Type) as logon_types
        min(_time) as firstTime max(_time) as lastTime
        by Source_Network_Address, ComputerName
| where count > 50
| convert ctime(firstTime) ctime(lastTime)
| sort - count
```
```
# Lockout storms — often the first thing the service desk notices
index=wineventlog EventCode=4740 earliest=-24h
| stats count values(Account_Name) as locked_accounts by Caller_Computer_Name
| sort - count
```

**Q5.3 — Any success from the attacking source (run this on every spray, always)**
```
index=azure_ad sourcetype="azure:aad:signin" earliest=-24h
  ipAddress IN ("<src_ip>")
| eval outcome=if('status.errorCode'==0,"SUCCESS","fail")
| stats count by userPrincipalName, outcome, appDisplayName, authenticationRequirement, conditionalAccessStatus
| where outcome="SUCCESS"
```
Also widen to the /24 and the ASN — a single-IP check misses rotating infrastructure.

**Q5.4 — Accounts where the password was correct but MFA held**
```
index=azure_ad sourcetype="azure:aad:signin" earliest=-24h
  ipAddress IN ("<src_ip>") "status.errorCode" IN (50076, 50079, 50074, 500121, 53003)
| stats count values("status.errorCode") as codes by userPrincipalName
```
Every account here gets a password reset. Notify the users.

**Q5.5 — Internal source: find the spraying process**
```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where DeviceName =~ "<internal source host>"
| where RemoteUrl has_any ("login.microsoftonline.com","sts.","adfs")
     or RemotePort in (389, 636, 88, 445)
| summarize Connections=count() by InitiatingProcessFileName, InitiatingProcessCommandLine,
            InitiatingProcessAccountName, RemoteUrl, RemotePort
| order by Connections desc
```
A legitimate application with stale credentials looks identical to an attack at the network layer. The process name and command line distinguish them.

**Q5.6 — MFA fatigue / push bombing**
```
index=azure_ad sourcetype="azure:aad:signin" earliest=-24h
  "status.errorCode" IN (0, 500121, 50074, 50097)
| rename userPrincipalName as user, ipAddress as src_ip
| sort 0 user _time
| streamstats count(eval('status.errorCode'==500121)) as denial_run by user
| streamstats current=f last(denial_run) as prior_denials by user
| where 'status.errorCode'==0 AND prior_denials >= 5
| table _time, user, src_ip, prior_denials, appDisplayName, "location.countryOrRegion"
```
Any hit → the user approved under pressure and the attacker has a session → **PB-04, P1.**

## Step 3 — Containment options
| Option | Effect | Trade-off |
|---|---|---|
| **Block source IP at the edge** | Stops that IP | Attackers rotate; low durability |
| **Block ASN / hosting-provider ranges in CA named locations** | Stops the whole infrastructure pool | Higher durability. Check no legitimate users egress via that ASN. |
| **CA policy: block legacy authentication** | Removes the most common MFA bypass | Breaks old clients — needs a Change and a comms plan. Highest-value control here. |
| **CA policy: require MFA for all users** | Closes the gap the attacker is hunting for | Needs break-glass accounts excluded and tested |
| **Enable MFA number matching** | Kills MFA fatigue attacks | Low impact, do it |
| **Tighten smart lockout** | Slows spray | Can be weaponised for DoS on user accounts — tune, don't max out |
| **Country/geo blocking in CA** | Cheap and effective if you have no legitimate users there | Travel exceptions needed |
| **Reset passwords for 50076/50079 accounts** | Closes actually-exposed credentials | Do it; these are real exposures |

## Step 4 — Verification
- [ ] Success check run against the IP, the /24, **and** the ASN (Q5.3)
- [ ] 50076/50079 accounts identified and passwords reset (Q5.4)
- [ ] Source blocked at the most durable layer available
- [ ] Internal-source possibility ruled out or investigated (Q5.5)
- [ ] MFA fatigue checked (Q5.6)
- [ ] MFA-coverage gap list produced and raised as a Change — **this is the real deliverable of a spray incident**
- [ ] Targeted-account list preserved (it's intelligence about the attacker's recon)

## Step 5 — ServiceNow
Category `Brute Force` / `Credential Attack`. Attach the targeted-account list and the block actions taken.
Every spray incident should generate at least one Change or Problem record — if it didn't, you treated the symptom.

---
---

# PB-09 · Privilege Escalation / Suspicious Admin Activity

**Default priority:** P2 · **P1** for tier-0 groups (Domain Admins, Enterprise Admins, Schema Admins, Global Administrator, Privileged Role Administrator, Application Administrator, Backup Operators, Account Operators)

## Step 1 — Decision tree
```
Privileged grant or admin action detected
│
├─ Is there a matching approved change record?
│   ├─ YES → verify the change actually authorised THIS grant to THIS person by THIS actor.
│   │        A change ticket for "onboard new admin" does not authorise adding a
│   │        different account. Close P4 if it matches exactly.
│   └─ NO  → continue. No change record is the primary signal.
│
├─ Did the ACTOR have authority to make this grant?
│   ├─ YES → contact the actor OUT-OF-BAND to confirm. If confirmed and it's a process
│   │        failure rather than an attack: close as policy violation, raise a Problem
│   │        record about change discipline.
│   └─ NO  → the actor's own account is likely compromised or has excess privilege.
│            → P1. Run PB-04 on the actor. Review everything they did.
│
├─ Is the TARGET account suspicious?
│   ├─ Newly created account (Q9.4)          → attacker-created persistence. P1.
│   ├─ Dormant account suddenly re-activated → P1. Classic persistence choice —
│   │                                            nobody notices a dormant account.
│   ├─ Service account gaining interactive
│   │  privilege                             → P1. Service accounts shouldn't need this.
│   ├─ The actor's own account (self-grant)   → P1. Nobody legitimately self-elevates
│   │                                            to Domain Admin.
│   └─ Normal user, plausible role change    → verify with their manager AND HR record
│
├─ Timing
│   ├─ Outside business hours / weekend / holiday → weight toward malicious
│   └─ During a known maintenance window          → weight toward legitimate, still verify
│
├─ Tier-0 involved?
│   └─ YES → P1 regardless of everything above. Assume domain compromise until
│            disproven. Engage SOC Lead + Infrastructure. Run PB-08.
│
└─ Other escalation techniques present? (Q9.5, Q9.6)
    ├─ DCSync / directory replication rights → P1. Full credential database at risk.
    │                                            KRBTGT reset will be needed.
    ├─ Kerberoasting (Q9.6)                  → P2. Rotate the targeted service account
    │                                            passwords; they're being cracked offline.
    ├─ AdminSDHolder / ACL modification      → P1. Persistent, subtle, survives group removal.
    ├─ GPO modification                      → P1. Domain-wide code execution primitive.
    └─ Golden/Silver ticket indicators       → P1. Full AD recovery planning.
```

## Step 2 — Queries

**Q9.1 — On-prem privileged group changes**
```
index=wineventlog earliest=-7d
  EventCode IN (4728, 4729, 4732, 4733, 4756, 4757, 4automatic)
| eval action=case(EventCode IN (4728,4732,4756),"ADDED",
                   EventCode IN (4729,4733,4757),"REMOVED")
| lookup privileged_groups.csv group_name as Group_Name OUTPUT tier
| where isnotnull(tier)
| table _time, tier, action, Group_Name, Member_Name, Subject_Account_Name, ComputerName
| sort _time
```

**Q9.2 — Entra ID role assignments**
```
index=azure_ad sourcetype="azure:aad:audit" earliest=-7d
  operationName IN ("Add member to role","Add eligible member to role",
                    "Add member to role in PIM requested (permanent)",
                    "Add member to role completed (PIM activation)",
                    "Add app role assignment to service principal",
                    "Add app role assignment grant to user",
                    "Add owner to application","Add owner to service principal")
| eval actor=coalesce('initiatedBy.user.userPrincipalName','initiatedBy.app.displayName'),
       target=coalesce('targetResources{}.userPrincipalName','targetResources{}.displayName'),
       role='targetResources{}.modifiedProperties{}.newValue'
| table _time, operationName, role, target, actor, result
| sort _time
```
> `initiatedBy.app.displayName` populated instead of a user means a **service principal** made the change. Service principals granting privileged roles is a strong indicator of compromise, and it's easy to miss because there's no human name attached.

**Q9.3 — Defender for Identity view**
```kql
IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType in ("Group Membership changed","Account Password changed",
        "SAM Account Name changed","Account Supported Encryption Types changed",
        "Delegated permissions changed","Account Constrained Delegation SPNs changed",
        "Account Constrained Delegation State changed","AdminSDHolder changed")
| project Timestamp, ActionType, AccountUpn, TargetAccountUpn, DestinationDeviceName, AdditionalFields
| order by Timestamp desc
```
```kql
// Privileged accounts appearing on non-admin workstations = credential exposure risk
IdentityLogonEvents
| where Timestamp > ago(7d)
| where AccountUpn in ("admin1@corp.com","admin2@corp.com")   // your tier-0 list
| where LogonType in ("Interactive","RemoteInteractive")
| summarize Logons=count(), Devices=make_set(DeviceName,50) by AccountUpn
```

**Q9.4 — New and modified accounts**
```
index=wineventlog earliest=-7d EventCode IN (4720, 4722, 4724, 4738, 4781, 4767)
| eval action=case(EventCode==4720,"CREATED", EventCode==4722,"ENABLED",
                   EventCode==4724,"PASSWORD RESET", EventCode==4738,"MODIFIED",
                   EventCode==4781,"RENAMED", EventCode==4767,"UNLOCKED")
| table _time, action, Account_Name, Target_Account_Name, Subject_Account_Name, ComputerName
| sort _time
```
Cross-reference every created account against HR onboarding. An account created outside the HR-driven process is either a shadow admin account (policy problem) or attacker persistence (incident).

**Q9.5 — DCSync / replication rights abuse**
```kql
IdentityDirectoryEvents
| where Timestamp > ago(30d)
| where ActionType == "Directory Services replication" or AdditionalFields has "DS-Replication"
| project Timestamp, ActionType, AccountUpn, DestinationDeviceName, AdditionalFields
```
```
index=wineventlog EventCode=4662 earliest=-30d
  Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*"
| table _time, Subject_Account_Name, Object_Name, ComputerName
```
That GUID is the DS-Replication-Get-Changes-All right. Any account other than your DCs and Azure AD Connect using it → **P1, full credential database compromise, KRBTGT reset required.**

**Q9.6 — Kerberoasting**
```
index=wineventlog EventCode=4769 earliest=-7d
  Ticket_Encryption_Type=0x17 Service_Name!="*$"
| stats dc(Service_Name) as services values(Service_Name) as service_list count
        by Account_Name, Client_Address
| where services > 5
| sort - services
```
`0x17` is RC4-HMAC. A single account requesting many RC4 service tickets in a short window is harvesting hashes for offline cracking. Rotate the passwords of every SPN in `service_list` — long, random, and ideally move them to Group Managed Service Accounts.

**Q9.7 — Full audit of everything an actor did (run this when the actor is suspect)**
```
index=azure_ad OR index=wineventlog OR index=o365 earliest=-30d
  ("initiatedBy.user.userPrincipalName"="suspect@corp.com"
   OR Subject_Account_Name="suspect" OR UserId="suspect@corp.com")
| stats count values(operationName) as aad_ops values(EventCode) as win_events
        values(Operation) as o365_ops by index, sourcetype
```
Then enumerate in detail per source. Every action needs a verdict: authorised or not.

## Step 3 — Containment options
| Option | When | Trade-off |
|---|---|---|
| **Reverse the grant** | Always, once confirmed unauthorised | Do it, but *after* you've captured the evidence and understood scope. Reversing first can tip off the attacker. |
| **Disable the target account** | Attacker-created or dormant-reactivated | |
| **Disable the actor account** | Actor compromised | Confirm out-of-band first — if the actor is a real admin you've just removed a responder |
| **Leave in place and monitor** | Only with SOC Lead approval, when you need to observe to find the full scope | Genuine risk. Time-boxed, documented, and only for tier-0 investigations with exec awareness. |
| **Full tier-0 credential rotation** | DCSync, golden ticket, or DC compromise | Major operation; plan with Infrastructure |
| **KRBTGT double reset** | Confirmed AD compromise | **Manual, planned, two stages with the required interval between them.** Do not script. Breaks authentication if rushed. |

## Step 4 — Verification
- [ ] Every unauthorised grant reversed and verified reversed
- [ ] Actor account status determined (compromised vs process failure) with evidence
- [ ] Full action audit of the actor completed (Q9.7), every action given a verdict
- [ ] New/modified accounts cross-referenced against HR
- [ ] DCSync, Kerberoasting, ACL and GPO changes checked (Q9.5, Q9.6)
- [ ] Tier-0 group memberships reconciled against the approved list
- [ ] If AD compromise: rotation plan agreed and tracked
- [ ] PIM/JIT gap raised as a Change if standing privilege was involved

## Step 5 — Prevention follow-ups (the actual value of this playbook)
Every PB-09 incident should produce at least one of:
- PIM / just-in-time activation for the role involved
- Approval workflow on privileged group changes
- Removal of standing privilege that wasn't needed
- Alerting on tier-0 changes with no matching change record (the correlation search ships in `savedsearches.conf`; wire in your change lookup to make it high-fidelity)
- Tiered admin model / privileged access workstations if admins are logging into user workstations (the MDI query in Q9.3 will tell you)

## Step 6 — ServiceNow
Category `Privilege Escalation` / `Unauthorized Access`. Impact 1 for tier-0.
Attach the reconciliation of current vs approved membership for every affected group.
Close notes must name the actor, the authority question ("did they have the right to do this"), and the answer.
