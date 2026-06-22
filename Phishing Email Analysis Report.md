============================================================
 PHISHING EMAIL ANALYSIS REPORT
============================================================

Analyst:        [Your Name]
Analysis Date:  [Today's Date]
Engagement:     Suspected Phishing Email Triage
Methodology:    Headers > Sender > Content > Links > Verdict


------------------------------------------------------------
 1. EMAIL METADATA
------------------------------------------------------------

Subject:        [e.g. "Your Microsoft 365 account has been suspended"]
From (display): [e.g. "Microsoft Security Team"]
From (actual):  [e.g. security-noreply@m1cr0soft-verify.com]
Reply-To:       [e.g. (same as From) or different address]
Date received:  [e.g. 14 Mar 2026 03:42 UTC]
Recipient:      [e.g. jane.doe@gmail.com]


------------------------------------------------------------
 2. EXECUTIVE SUMMARY
------------------------------------------------------------

[Two to three sentences with verdict and reasoning.
 Example: "Email confirmed as phishing. Sender domain
 m1cr0soft-verify.com is a typosquat of microsoft.com,
 registered 6 days ago via a registrar commonly abused
 for phishing campaigns. The embedded link redirects to
 a credential-harvesting page styled as the Microsoft
 login screen. No legitimate Microsoft communication
 originates from this domain."]


------------------------------------------------------------
 3. HEADER ANALYSIS
------------------------------------------------------------

SPF:            [e.g. FAIL — sender IP not authorised for the
                 claimed domain]
DKIM:           [e.g. NONE — no signature present]
DMARC:          [e.g. FAIL — alignment failed]

Originating IP: [e.g. 185.243.214.97]
IP Geolocation: [e.g. Russia / Moscow]
Reverse DNS:    [e.g. no reverse record found]


------------------------------------------------------------
 4. SENDER DOMAIN ANALYSIS
------------------------------------------------------------

Domain:           [e.g. m1cr0soft-verify.com]
Registered on:    [e.g. 8 Mar 2026 (6 days before email sent)]
Registrar:        [e.g. NameSilo]
Privacy enabled:  [e.g. Yes]
Domain age:       [e.g. 6 days]
Lookalike of:     [e.g. microsoft.com — typosquat using "1" for "i"]


------------------------------------------------------------
 5. CONTENT INDICATORS
------------------------------------------------------------

  [x] Urgency: "Your account will be suspended in 24 hours"
  [x] Generic greeting: "Dear Customer"
  [x] Spelling/grammar errors: [list them, e.g. "verifiy"]
  [x] Mismatched branding: [e.g. logo is low-resolution]
  [x] Authority impersonation: claims to be Microsoft
  [ ] Threat: [e.g. "legal action will be taken"]
  [ ] Reward bait: [e.g. "you have won..."]


------------------------------------------------------------
 6. LINK ANALYSIS
------------------------------------------------------------

Visible link text:  [e.g. "Click here to verify your account"]
Actual URL:         [e.g. https://ms-account-verify.cf/login]
Destination domain: [e.g. ms-account-verify.cf]
URL shortener:      [e.g. No / Yes — bit.ly]
HTTPS:              [e.g. Yes — but free Let's Encrypt cert
                     issued 3 days ago]
Landing page:       [e.g. Microsoft login page clone]


------------------------------------------------------------
 7. VERDICT
------------------------------------------------------------

Classification:   [PHISHING / SPAM / LEGITIMATE / UNCERTAIN]
Confidence:       [HIGH / MEDIUM / LOW]
Severity:         [HIGH / MEDIUM / LOW]

Reasoning: [One paragraph explaining the verdict. Cite the
strongest evidence — typosquatted domain, recent registration,
failed authentication, credential-harvesting landing page.]


------------------------------------------------------------
 8. RECOMMENDED ACTIONS
------------------------------------------------------------

If you received this email:
  [x] [e.g. Do not click any links]
  [x] [e.g. Report to your email provider (mark as phishing)]
  [x] [e.g. Forward to phishing@microsoft.com if impersonating]
  [x] [e.g. Delete after reporting]

If you clicked the link:
  [ ] [e.g. Change password on the real Microsoft account]
  [ ] [e.g. Enable 2FA if not already on]
  [ ] [e.g. Check account for unauthorised sessions]
  [ ] [e.g. Scan device for malware]


============================================================
 END OF REPORT
============================================================
