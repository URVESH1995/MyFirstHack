<#
.SYNOPSIS
    Identity containment for PB-04 (Account Compromise) and PB-01 Branch C.

.DESCRIPTION
    Performs the containment sequence in the order the runbook requires:
    revoke sessions FIRST (kills stolen tokens), then optionally block sign-in,
    clear forwarding, and remove malicious inbox rules.

    Every action is written to a transcript file for attachment to the SIR.

    WHY REVOKE BEFORE RESET
    Adversary-in-the-middle phishing kits steal the session token, not the
    password. A password reset alone leaves the attacker's session alive.
    Revocation invalidates refresh tokens; that is the control that works.

.WHAT THIS SCRIPT DOES NOT DO — deliberately
    * It does not reset passwords. Password resets need a human to deliver the
      credential out-of-band (phone call to a known number). Automating that
      creates a plaintext credential in a log or a console buffer. Use the
      Entra portal or your service desk process, and never email it.
    * It does not delete data.
    * It does not remove OAuth consents automatically — those need human review
      of the granted scopes first, because deleting the wrong enterprise
      application breaks production. It reports them for you to action.

.PARAMETER UserPrincipalName
    The compromised account.

.PARAMETER RevokeSessions
    Invalidate refresh tokens. Do this first, always.

.PARAMETER BlockSignIn
    Set accountEnabled = false. Remember to unblock — set a reminder.

.PARAMETER ClearForwarding
    Remove mailbox-level forwarding (separate from inbox rules; check both).

.PARAMETER RemoveInboxRules
    Remove inbox rules. Prompts per rule. Rules are exported to evidence first.

.PARAMETER CollectEvidence
    Run the full evidence collection (rules, delegation, OAuth, auth methods,
    devices, protocol settings, recent sign-ins) and write it to a file.

.PARAMETER Ticket
    SIR number. Used in the evidence filename and in logging.

.PARAMETER WhatIf
    Show what would happen without doing it. Use this first.

.EXAMPLE
    .\Invoke-IdentityContainment.ps1 -UserPrincipalName victim@corp.com `
        -RevokeSessions -CollectEvidence -Ticket SIR0012345

.EXAMPLE
    # Full containment for a confirmed compromise with persistence
    .\Invoke-IdentityContainment.ps1 -UserPrincipalName victim@corp.com `
        -RevokeSessions -BlockSignIn -ClearForwarding -RemoveInboxRules `
        -CollectEvidence -Ticket SIR0012345

.NOTES
    Modules:  Microsoft.Graph.Users, Microsoft.Graph.Identity.SignIns,
              Microsoft.Graph.Applications, ExchangeOnlineManagement
    Graph scopes: User.ReadWrite.All, User.RevokeSessions.All, Directory.Read.All,
                  AuditLog.Read.All, Application.Read.All
    Exchange role: at minimum a role that grants Get/Remove-InboxRule and Set-Mailbox.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)][string]$UserPrincipalName,
    [switch]$RevokeSessions,
    [switch]$BlockSignIn,
    [switch]$ClearForwarding,
    [switch]$RemoveInboxRules,
    [switch]$CollectEvidence,
    [string]$Ticket = "NO-TICKET",
    [string]$EvidencePath = ".\evidence"
)

$ErrorActionPreference = 'Stop'
$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmssZ")
$safeUser = $UserPrincipalName -replace '[^\w\.\-]', '_'
if (-not (Test-Path $EvidencePath)) { New-Item -ItemType Directory -Path $EvidencePath | Out-Null }
$logFile = Join-Path $EvidencePath "$Ticket-$safeUser-$stamp.log"
$evFile  = Join-Path $EvidencePath "$Ticket-$safeUser-$stamp-evidence.txt"

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "{0} [{1}] {2}" -f (Get-Date).ToUniversalTime().ToString("s"), $Level, $Message
    Write-Host $line
    Add-Content -Path $logFile -Value $line
}

function Write-Evidence {
    param([string]$Section, $Data)
    Add-Content -Path $evFile -Value "`n=========== $Section ==========="
    if ($null -eq $Data) { Add-Content -Path $evFile -Value "(none)"; return }
    Add-Content -Path $evFile -Value ($Data | Format-List | Out-String)
}

Write-Log "=== Identity containment started ==="
Write-Log "Target: $UserPrincipalName | Ticket: $Ticket | Operator: $env:USERNAME"
Write-Log "Evidence: $evFile"

if (-not ($RevokeSessions -or $BlockSignIn -or $ClearForwarding -or $RemoveInboxRules -or $CollectEvidence)) {
    Write-Log "No action switches supplied. Nothing to do." 'WARN'
    Write-Host "`nSpecify at least one of: -RevokeSessions -BlockSignIn -ClearForwarding -RemoveInboxRules -CollectEvidence"
    exit 1
}

# --------------------------------------------------------------------- connect
try {
    $ctx = Get-MgContext
    if (-not $ctx) {
        Write-Log "Connecting to Microsoft Graph..."
        Connect-MgGraph -Scopes "User.ReadWrite.All", "User.RevokeSessions.All",
            "Directory.Read.All", "AuditLog.Read.All", "Application.Read.All" -NoWelcome
    }
    Write-Log "Graph connected as $((Get-MgContext).Account)"
} catch {
    Write-Log "Graph connection failed: $_" 'ERROR'; exit 1
}

try {
    $user = Get-MgUser -UserId $UserPrincipalName -Property Id, UserPrincipalName, DisplayName,
        AccountEnabled, CreatedDateTime, LastPasswordChangeDateTime, JobTitle, Department
    Write-Log "Resolved: $($user.DisplayName) ($($user.Id)) | Enabled=$($user.AccountEnabled) | Dept=$($user.Department)"
} catch {
    Write-Log "User not found: $UserPrincipalName" 'ERROR'; exit 1
}

$exchangeConnected = $false
if ($ClearForwarding -or $RemoveInboxRules -or $CollectEvidence) {
    try {
        if (-not (Get-ConnectionInformation -ErrorAction SilentlyContinue)) {
            Write-Log "Connecting to Exchange Online..."
            Connect-ExchangeOnline -ShowBanner:$false
        }
        $exchangeConnected = $true
        Write-Log "Exchange Online connected"
    } catch {
        Write-Log "Exchange connection failed: $_ — mailbox actions will be skipped" 'WARN'
    }
}

# ------------------------------------------------- 1. EVIDENCE (before changes)
if ($CollectEvidence) {
    Write-Log "--- Collecting evidence (before any changes) ---"
    Add-Content -Path $evFile -Value "IDENTITY COMPROMISE EVIDENCE`nUser: $UserPrincipalName`nTicket: $Ticket`nCollected: $stamp by $env:USERNAME"

    Write-Evidence "USER OBJECT" $user

    try {
        $methods = Get-MgUserAuthenticationMethod -UserId $user.Id
        $methodSummary = $methods | ForEach-Object {
            [pscustomobject]@{
                Type = ($_.AdditionalProperties['@odata.type'] -replace '#microsoft.graph.', '')
                Id   = $_.Id
                Detail = ($_.AdditionalProperties.GetEnumerator() |
                          Where-Object { $_.Key -ne '@odata.type' } |
                          ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; '
            }
        }
        Write-Evidence "AUTHENTICATION METHODS  <-- check for any registered during the compromise window" $methodSummary
        Write-Log "Auth methods: $($methods.Count) registered"
    } catch { Write-Log "Auth method enumeration failed: $_" 'WARN' }

    try {
        $grants = Get-MgOauth2PermissionGrant -Filter "principalId eq '$($user.Id)'" -All
        $grantDetail = foreach ($g in $grants) {
            try { $sp = Get-MgServicePrincipal -ServicePrincipalId $g.ClientId } catch { $sp = $null }
            [pscustomobject]@{
                App        = if ($sp) { $sp.DisplayName } else { $g.ClientId }
                Publisher  = if ($sp) { $sp.PublisherName } else { 'unknown' }
                AppId      = if ($sp) { $sp.AppId } else { '' }
                ConsentType= $g.ConsentType
                Scopes     = $g.Scope
                HighRisk   = if ($g.Scope -match 'Mail\.(Read|ReadWrite|Send)|Files\.ReadWrite|offline_access|Directory\.ReadWrite') { 'YES - REVIEW' } else { '' }
            }
        }
        Write-Evidence "OAUTH DELEGATED GRANTS  <-- HighRisk=YES survives password reset AND session revoke" $grantDetail
        $risky = ($grantDetail | Where-Object HighRisk).Count
        Write-Log "OAuth grants: $($grants.Count) total, $risky flagged high-risk"
        if ($risky -gt 0) {
            Write-Log "ACTION REQUIRED: review and revoke high-risk OAuth grants manually in Entra -> Enterprise applications" 'WARN'
        }
    } catch { Write-Log "OAuth grant enumeration failed: $_" 'WARN' }

    try {
        $devices = Get-MgUserRegisteredDevice -UserId $user.Id -All
        Write-Evidence "REGISTERED DEVICES  <-- any created during the window is attacker persistence" (
            $devices | ForEach-Object {
                [pscustomobject]@{
                    Name    = $_.AdditionalProperties['displayName']
                    Created = $_.AdditionalProperties['createdDateTime']
                    OS      = $_.AdditionalProperties['operatingSystem']
                    Trust   = $_.AdditionalProperties['trustType']
                    Id      = $_.Id
                }
            })
        Write-Log "Registered devices: $($devices.Count)"
    } catch { Write-Log "Device enumeration failed: $_" 'WARN' }

    try {
        $since = (Get-Date).AddDays(-14).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $signins = Get-MgAuditLogSignIn -Filter "userPrincipalName eq '$UserPrincipalName' and createdDateTime ge $since" -Top 200
        Write-Evidence "SIGN-INS (14 days)" (
            $signins | ForEach-Object {
                [pscustomobject]@{
                    Time    = $_.CreatedDateTime
                    IP      = $_.IpAddress
                    Country = $_.Location.CountryOrRegion
                    City    = $_.Location.City
                    App     = $_.AppDisplayName
                    Status  = $_.Status.ErrorCode
                    Client  = $_.ClientAppUsed
                    Risk    = $_.RiskLevelDuringSignIn
                    MFA     = $_.AuthenticationRequirement
                }
            } | Sort-Object Time)
        Write-Log "Sign-in records retrieved: $($signins.Count)"
    } catch { Write-Log "Sign-in log retrieval failed: $_" 'WARN' }

    if ($exchangeConnected) {
        try {
            $rules = Get-InboxRule -Mailbox $UserPrincipalName -ErrorAction Stop
            Write-Evidence "INBOX RULES  <-- forwarding/deleting rules = HUMAN OPERATOR, escalate to P1" (
                $rules | Select-Object Name, Enabled, Priority, Description, ForwardTo,
                    ForwardAsAttachmentTo, RedirectTo, DeleteMessage, MoveToFolder,
                    MarkAsRead, StopProcessingRules, From, SubjectContainsWords, BodyContainsWords)
            Write-Log "Inbox rules: $($rules.Count)"
            $suspicious = $rules | Where-Object {
                $_.ForwardTo -or $_.RedirectTo -or $_.ForwardAsAttachmentTo -or
                $_.DeleteMessage -eq $true -or
                ($_.MoveToFolder -match 'RSS|Conversation History|Archive|Junk|Deleted') -or
                [string]::IsNullOrWhiteSpace($_.Name) -or $_.Name.Length -le 2
            }
            if ($suspicious) {
                Write-Log "SUSPICIOUS RULES FOUND: $($suspicious.Count) — escalate to P1" 'WARN'
                $suspicious | ForEach-Object { Write-Log "   Rule '$($_.Name)': fwd=$($_.ForwardTo) del=$($_.DeleteMessage) move=$($_.MoveToFolder)" 'WARN' }
            }
        } catch { Write-Log "Inbox rule enumeration failed: $_" 'WARN' }

        try {
            $mbx = Get-Mailbox $UserPrincipalName
            Write-Evidence "MAILBOX FORWARDING (separate from rules — check both)" (
                $mbx | Select-Object ForwardingAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward)
            if ($mbx.ForwardingSmtpAddress -or $mbx.ForwardingAddress) {
                Write-Log "MAILBOX-LEVEL FORWARDING SET: $($mbx.ForwardingSmtpAddress)$($mbx.ForwardingAddress)" 'WARN'
            }

            Write-Evidence "PROTOCOL SETTINGS (legacy auth bypasses CA/MFA)" (
                Get-CASMailbox $UserPrincipalName | Select-Object ImapEnabled, PopEnabled,
                    SmtpClientAuthenticationDisabled, EwsEnabled, ActiveSyncEnabled, OWAEnabled)

            Write-Evidence "MAILBOX PERMISSIONS" (
                Get-MailboxPermission -Identity $UserPrincipalName |
                Where-Object { $_.User -notlike 'NT AUTHORITY*' -and -not $_.IsInherited })

            Write-Evidence "RECIPIENT (SEND-AS) PERMISSIONS" (
                Get-RecipientPermission -Identity $UserPrincipalName |
                Where-Object { $_.Trustee -notlike 'NT AUTHORITY*' })

            $exports = Get-MailboxExportRequest -Mailbox $UserPrincipalName -ErrorAction SilentlyContinue
            if ($exports) {
                Write-Evidence "MAILBOX EXPORT REQUESTS  <-- bulk mailbox theft" $exports
                Write-Log "MAILBOX EXPORT REQUESTS FOUND — probable bulk exfiltration" 'WARN'
            }
        } catch { Write-Log "Mailbox evidence collection partial: $_" 'WARN' }
    }
    Write-Log "Evidence written to $evFile"
}

# --------------------------------------------------- 2. REVOKE SESSIONS (first)
if ($RevokeSessions) {
    if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Revoke all sign-in sessions")) {
        try {
            Revoke-MgUserSignInSession -UserId $user.Id | Out-Null
            Write-Log "SESSIONS REVOKED for $UserPrincipalName"
            Write-Log "NOTE: access tokens may remain valid for up to ~1 hour on apps without Continuous Access Evaluation. Verify with PB-04 Q4.6 at 1h/4h/24h."
        } catch { Write-Log "Session revocation FAILED: $_" 'ERROR' }
    }
}

# ------------------------------------------------------------- 3. BLOCK SIGN-IN
if ($BlockSignIn) {
    if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Block sign-in (accountEnabled = false)")) {
        try {
            Update-MgUser -UserId $user.Id -AccountEnabled:$false
            Write-Log "SIGN-IN BLOCKED for $UserPrincipalName"
            Write-Log "REMINDER: set a task to unblock. A blocked user with no follow-up becomes its own incident." 'WARN'
        } catch { Write-Log "Sign-in block FAILED: $_" 'ERROR' }
    }
}

# ---------------------------------------------------------- 4. CLEAR FORWARDING
if ($ClearForwarding -and $exchangeConnected) {
    if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Clear mailbox-level forwarding")) {
        try {
            Set-Mailbox -Identity $UserPrincipalName -ForwardingAddress $null `
                        -ForwardingSmtpAddress $null -DeliverToMailboxAndForward $false
            Write-Log "Mailbox-level forwarding cleared"
        } catch { Write-Log "Clear forwarding FAILED: $_" 'ERROR' }
    }
}

# ------------------------------------------------------- 5. REMOVE INBOX RULES
if ($RemoveInboxRules -and $exchangeConnected) {
    try {
        $rules = Get-InboxRule -Mailbox $UserPrincipalName
        if (-not $rules) {
            Write-Log "No inbox rules present"
        } else {
            Write-Log "--- Inbox rule review ($($rules.Count) rules) ---"
            foreach ($r in $rules) {
                Write-Host ""
                Write-Host "  Name:        $($r.Name)"          -ForegroundColor Cyan
                Write-Host "  Enabled:     $($r.Enabled)"
                Write-Host "  ForwardTo:   $($r.ForwardTo)"
                Write-Host "  RedirectTo:  $($r.RedirectTo)"
                Write-Host "  Delete:      $($r.DeleteMessage)"
                Write-Host "  MoveTo:      $($r.MoveToFolder)"
                Write-Host "  Conditions:  $($r.Description -replace '\s+',' ')"
                if ($PSCmdlet.ShouldProcess("$UserPrincipalName rule '$($r.Name)'", "Remove inbox rule")) {
                    try {
                        Remove-InboxRule -Mailbox $UserPrincipalName -Identity $r.Identity -Confirm:$false
                        Write-Log "Removed inbox rule: '$($r.Name)'"
                    } catch { Write-Log "Failed to remove rule '$($r.Name)': $_" 'ERROR' }
                }
            }
        }
    } catch { Write-Log "Inbox rule removal failed: $_" 'ERROR' }
}

# -------------------------------------------------------------------- 6. SUMMARY
Write-Log "=== Containment run complete ==="

Write-Host ""
Write-Host "MANUAL STEPS STILL REQUIRED (this script deliberately does not do these):" -ForegroundColor Yellow
Write-Host "  1. Reset the password. Deliver it OUT-OF-BAND (phone to a known number)."
Write-Host "     Never email it — the mailbox may be attacker-controlled."
Write-Host "  2. Review authentication methods and DELETE any registered during the"
Write-Host "     compromise window, then require re-registration."
Write-Host "  3. Review the OAUTH GRANTS section of the evidence file. Revoke any"
Write-Host "     high-risk grant in Entra -> Enterprise applications -> Permissions."
Write-Host "     An OAuth grant survives password reset AND session revocation."
Write-Host "  4. Remove attacker-registered devices (Entra -> Devices)."
Write-Host "  5. Contain user in Defender XDR (incident page -> user entity -> Contain user)."
Write-Host "  6. Block attacker IP/ASN in Conditional Access named locations."
Write-Host "  7. Verify containment held: run PB-04 Q4.6 at 1h, 4h and 24h."
Write-Host "  8. Attach $evFile and $logFile to $Ticket."
Write-Host ""
Write-Host "Log:      $logFile" -ForegroundColor Green
Write-Host "Evidence: $evFile" -ForegroundColor Green
