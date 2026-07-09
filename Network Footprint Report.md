============================================================
 NETWORK FOOTPRINT REPORT
============================================================

Analyst:        [Your Name]
Analysis Date:  [Today's Date]
Engagement:     Passive Reconnaissance of [Target Domain]
Methodology:    DNS > WHOIS > Certificates > Technology


------------------------------------------------------------
 1. TARGET SUMMARY
------------------------------------------------------------

Domain:          [e.g. example-shop.com]
Description:     [e.g. Small online clothing retailer]
Reason chosen:   [e.g. Real small-business website for analysis]
Scope:           Passive reconnaissance only — public sources
                 only, no scanning, no probing, no interaction
                 with target infrastructure


------------------------------------------------------------
 2. EXECUTIVE SUMMARY
------------------------------------------------------------

[Two to three sentences summarising what the public footprint
 reveals. Example: "Target operates on Shopify with Cloudflare
 in front of the origin. DNS shows mail handled by Google
 Workspace. Three subdomains discovered via certificate
 transparency — including a staging environment that appears
 publicly resolvable. WHOIS shows a 4-year-old domain
 registered via GoDaddy with privacy protection enabled."]


------------------------------------------------------------
 3. DNS RECORDS
------------------------------------------------------------

A record(s):       [e.g. 104.21.45.182, 172.67.198.74
                   — both Cloudflare-owned ranges]
MX record(s):      [e.g. aspmx.l.google.com — Google Workspace]
NS record(s):      [e.g. dana.ns.cloudflare.com,
                   ed.ns.cloudflare.com — Cloudflare DNS]
TXT record(s):     [e.g. SPF: v=spf1 include:_spf.google.com ~all
                   Google site verification token]
Other notable:     [e.g. CNAME for shopify-store.myshopify.com]


------------------------------------------------------------
 4. WHOIS
------------------------------------------------------------

Registrar:         [e.g. GoDaddy.com, LLC]
Registration date: [e.g. 14 May 2022]
Expiration date:   [e.g. 14 May 2027]
Registrant:        [e.g. Privacy protected — Domains by Proxy]
Contact email:     [e.g. Privacy protected]
Domain age:        [e.g. 4 years (healthy for established brand)]


------------------------------------------------------------
 5. CERTIFICATE TRANSPARENCY
------------------------------------------------------------

Total certs issued: [e.g. 47]
CA used most:       [e.g. Let's Encrypt — automated renewal]
Subdomains found:   [list any interesting subdomains, e.g.
                     - www.example-shop.com
                     - shop.example-shop.com
                     - staging.example-shop.com
                     - admin.example-shop.com]
Notable findings:   [e.g. staging.example-shop.com appears
                     active and publicly resolvable — common
                     forgotten-environment exposure pattern]


------------------------------------------------------------
 6. TECHNOLOGY PROFILE
------------------------------------------------------------

Server software:   [e.g. cloudflare (reverse proxy)]
CMS/framework:     [e.g. Shopify]
Analytics:         [e.g. Google Analytics, Facebook Pixel]
Hosting provider:  [e.g. Shopify origin behind Cloudflare]
Other tech:        [e.g. jQuery 3.5.1, Klaviyo email marketing,
                    Hotjar session recording]


------------------------------------------------------------
 7. OBSERVATIONS
------------------------------------------------------------

[Two or three sentences on what stood out from the analysis.
 Example: "The staging environment exposure is the most
 notable finding — it's a common pattern where development
 environments are forgotten in DNS but still serve traffic.
 The technology stack is appropriate for the business size.
 Domain age and registrar are unremarkable, suggesting an
 established, legitimate operation."]


------------------------------------------------------------
 8. RECOMMENDATIONS
------------------------------------------------------------

If briefing the target's security team:
  [ ] [e.g. Assess staging.example-shop.com for inadvertent
          information disclosure; restrict to authenticated
          access or remove from public DNS]
  [ ] [e.g. Confirm Shopify origin IP is not publicly reachable
          outside of Cloudflare]
  [ ] [e.g. Review WHOIS privacy settings are aligned with
          internal policy]


============================================================
 END OF REPORT
============================================================
