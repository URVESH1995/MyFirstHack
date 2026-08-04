============================================================
 NETWORK DEFENSE PLAN
============================================================

Prepared by:    [Your Name]
Date:           [Today's Date]
Client:         Maya's Clothing Shop (small retail business)
Engagement:     Network Security Assessment and Remediation Plan


------------------------------------------------------------
 1. ASSESSMENT SUMMARY
------------------------------------------------------------

[Two to four sentences: the overall state of the network, the
 headline risks, and the single most urgent priority. Example:
 "Maya's network is a single flat network with no segmentation,
 exposing payment systems to customer Wi-Fi and to insecure IoT
 devices. The most urgent risk is the lack of segmentation
 combined with weak Wi-Fi access. With a small number of
 affordable, prioritised changes, the network can be made
 substantially more defensible."]


------------------------------------------------------------
 2. NETWORK INVENTORY
------------------------------------------------------------

Device / system          Category          Holds / does
[e.g. Payment till x2     Payment           Card transactions]
[e.g. Security cameras x4 IoT               Never updated]
[e.g. Back-office laptop  Data              Customer records]
[e.g. Maya's laptop       Personal          Business + home use]
[e.g. Staff phones x2     Staff             Connect to shop Wi-Fi]
[e.g. Smart speaker       IoT               Brought in]
[e.g. Network printer     Infrastructure    Shared]
[e.g. Customer Wi-Fi      Guest             Shares main network]
[e.g. ISP router          Infrastructure    Default admin password]


------------------------------------------------------------
 3. PRIORITISED RISKS
------------------------------------------------------------

CRITICAL
  [ ] [e.g. Flat network: any compromised device reaches the
          payment tills and customer data. No barriers to
          lateral movement.]
  [ ] [e.g. Customer Wi-Fi shares the network with payment
          systems (also a PCI DSS compliance failure).]
  [ ] [e.g. Default router admin credentials — trivial takeover.]

HIGH
  [ ] [e.g. Weak shared Wi-Fi password, unchanged 3 years,
          written publicly — crackable and exposed.]
  [ ] [e.g. No monitoring or logs — an attack would go
          unnoticed and couldn't be investigated.]

MEDIUM
  [ ] [e.g. Four never-updated IoT cameras — vulnerable and
          unsegmented (echoes the Mirai botnet).]
  [ ] [e.g. Shared back-office laptop with customer data — no
          access control / least privilege.]

LOW
  [ ] [e.g. Unmanaged smart speaker on the network.]


------------------------------------------------------------
 4. RECOMMENDED FIXES
------------------------------------------------------------

[For each risk above, a specific, realistic fix. Examples:]

  - [e.g. SEGMENT the network: separate networks for (a) payment
     systems, (b) customer Wi-Fi, (c) IoT/cameras, (d) staff and
     office. Most modern routers support guest + IoT networks.]
  - [e.g. CHANGE the router admin password from the default to a
     strong unique one; update router firmware.]
  - [e.g. Set Wi-Fi to WPA3 (or WPA2 minimum) with a long unique
     password, NOT shared with customers or written in public.]
  - [e.g. Enable basic logging; consider an affordable managed
     security/monitoring service as the business grows.]
  - [e.g. Restrict the back-office laptop / customer data to
     only the people who need it (least privilege).]


------------------------------------------------------------
 5. PHASED ACTION PLAN
------------------------------------------------------------

DO FIRST (critical, highest leverage):
  [ ] [e.g. Change default router credentials]
  [ ] [e.g. Segment payment systems and customer Wi-Fi apart]

THIS WEEK:
  [ ] [e.g. New strong Wi-Fi password, WPA3 if supported]
  [ ] [e.g. Separate IoT cameras onto their own segment]

THIS MONTH:
  [ ] [e.g. Set up logging / managed monitoring]
  [ ] [e.g. Tidy access control on the back-office data]
  [ ] [e.g. Review the smart speaker and any other extras]


------------------------------------------------------------
 6. HOW MAYA WILL KNOW IT WORKED
------------------------------------------------------------

[Two or three concrete checks Maya (or her provider) can make.
 Example: "Customer devices can no longer reach the till
 network; the router admin login no longer uses the default
 password; Wi-Fi shows WPA3; logging is active and reviewed."]


============================================================
 END OF PLAN
============================================================
