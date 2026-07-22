============================================================
 TRAFFIC INVESTIGATION REPORT
============================================================

Analyst:        [Your Name]
Analysis Date:  [Today's Date]
Engagement:     Network Traffic Capture Investigation
Methodology:    Orient > Question > Filter > Follow > Compare > Document


------------------------------------------------------------
 1. CAPTURE SUMMARY
------------------------------------------------------------

Source:          [e.g. Wireshark sample capture "http_with_jpegs.pcap"
                  / my own capture of varied browsing]
Total packets:   [e.g. 3,412]
Time span:       [e.g. 4 minutes 18 seconds]
Headline:        [One or two sentences — the single most important
                  finding. Example: "Capture shows ordinary web
                  browsing with no anomalies" OR "Capture contains
                  what appears to be a port scan from a single
                  external host."]


------------------------------------------------------------
 2. ORIENTATION
------------------------------------------------------------

Top protocols (from Protocol Hierarchy):
  - [e.g. TCP 68%, TLS 41%, DNS 6%, ARP 2%]

Busiest conversation (from Conversations, sorted by bytes):
  - [e.g. 192.168.1.50 <-> 142.250.187.78, 1.2 MB exchanged]

Notable endpoints (from Endpoints):
  - [e.g. one host (192.168.1.50) talked to 40+ addresses;
     all destinations resolved to recognisable services]
     [or "nothing notable"]


------------------------------------------------------------
 3. INVESTIGATION
------------------------------------------------------------

Question chased:
  [e.g. "Why did one host connect to so many addresses in
   a short window?"]

Filters used:
  [e.g. ip.addr == 192.168.1.50
        tcp.flags.syn == 1 && tcp.flags.ack == 0
        dns]

What I found following the thread:
  [Two to four sentences describing what the investigation
   revealed. Be specific about what the packets showed.]


------------------------------------------------------------
 4. COMPARISON TO BASELINE
------------------------------------------------------------

Assessed against normal-traffic baseline and known attack
patterns (port scan / suspicious DNS / beacon / plaintext):

  [ ] Normal traffic — DNS precedes connections, clean
      handshakes and teardowns, recognisable destinations
  [ ] Port scan signature observed
  [ ] Suspicious DNS observed
  [ ] Beacon pattern observed
  [ ] Plaintext exposure observed
  [ ] Other / unexplained

Evidence for the box(es) checked:
  [e.g. "Filter tcp.flags.reset == 1 showed 180 RST packets
   all responding to SYNs from 203.0.113.45 to sequential
   ports 1-1024 within 3 seconds — classic port-scan
   signature."]


------------------------------------------------------------
 5. VERDICT AND CONFIDENCE
------------------------------------------------------------

Verdict:     [e.g. Normal traffic / Port scan detected /
              Unexplained anomaly]
Confidence:  [CERTAIN / PROBABLE / UNEXPLAINED-BUT-ODD]

Reasoning:   [One paragraph. State what the evidence supports
              and no more. If confidence is low, say why. If
              you found nothing suspicious, state that clearly
              and confidently.]


------------------------------------------------------------
 6. RECOMMENDED NEXT STEPS
------------------------------------------------------------

If this were a real engagement:
  [ ] [e.g. Capture additional traffic from the same host to
          confirm the beacon interval]
  [ ] [e.g. Check the suspicious external IP against threat
          intelligence (AbuseIPDB, etc)]
  [ ] [e.g. No further action — traffic is benign]


============================================================
 END OF REPORT
============================================================
