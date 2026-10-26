Local Adaptive Firewall: Project Proposal 

# Local Adaptive Firewall: Project Proposal 

Oct 25, 2026 · @Andy 

## Problem statement 

Devices on home, campus and small-business networks still receive hostile traffic that nothing explains to the owner, and most existing tools are either too expert-oriented or too silent to help. 

- **What arrives:** port scans, exploit attempts, brute-force logins, malware downloads, command-and-control beaconing and data exfiltration such as DNS tunneling. 

- **Honest scope:** TLS and IPsec already detect tampering in transit, so a local packet scanner adds most value on plaintext protocols, connection behaviour and processlevel attribution. Most traffic is encrypted, so detection must rely on flow patterns (timing, sizes, destinations) and which process owns the connection, not payload text alone. 

- **Gap in existing tools:** Snort, Suricata and Zeek are powerful but need expertise. Consumer firewalls block silently or show jargon. Published ML intrusion detectors rarely ship as per-device, explainable tools. 

**Problem statement:** build a lightweight firewall that lives on the device, inspects all inbound traffic locally, blocks malicious packets in real time, and tells the owner in plain language what was blocked and why, without sending traffic data off the machine. 

## Proposed solution 

The firewall decides in milliseconds by running cheap checks first and expensive ones last, and it keeps any language model off the packet path. 

1. **Capture and enforcement:** nftables with NFQUEUE or eBPF on Linux, WinDivert or WFP on Windows. 

2. **Reputation:** IP and domain blocklists held in a Bloom filter (microseconds per lookup). 

3. **Signatures and protocol sanity:** Aho-Corasick multi-pattern matching, Snort/Suricatastyle rules, checks for malformed headers and illegal TCP flag combinations. 

4. **Behaviour rules:** port-scan detection, connection-rate limits, and per-process attribution (for example, a text editor should never talk to the internet). 

Page 1 of 10 

Local Adaptive Firewall: Project Proposal 

5. **ML on flow features:** Random Forest or gradient boosting, plus an autoencoder trained on the machine's own normal traffic to catch anomalies. Inference stays well under a millisecond. 

6. **Decision engine:** fuses the scores into allow, block or quarantine, then raises an OS notification with the reason and an "allow once" button. 

7. **Slow lane (optional):** a small language model that turns collected evidence into plainlanguage alerts and triages odd events asynchronously. 



<!-- Start of picture text -->
Cheap checks run first; the language model stays off the packet path<br>Incoming packet<br>1Reputation 2 Signatures 3 Behaviour 4 Flow model<br>Known-bad lists Rules, bad headers Scans, floods, rates Flow-feature model<br>Decision engine: fuse scores into allow, block or quarantine<br>Allow Block and log Alert the owner Slow lane<br>Packet passes Evidence saved Reason, allow once Optional small model<br>Off the packet path<br><!-- End of picture text -->

firewall architecture · 4 detection stages, 1 decision, 4 outcomes 

Each stage can stop a packet early, and the optional language model only explains events after the decision has been made. 

### Does it need an LLM? 

No, not for the block decision. Even a tiny transformer takes milliseconds per input on a CPU, while a firewall handles thousands of packets a second. An LLM does not automatically improve detection either; the hard parts are false positives and generalizing to unseen traffic. Alert text such as "150 ports probed in 3 seconds from one address" can come from templates filled with the detector's own evidence. If a model is used, run it offpath. Approximate sizes (int8) from memory: 

Page 2 of 10 

Local Adaptive Firewall: Project Proposal 

|Option|Parameters|Approx. size|Role|
|---|---|---|---|
|Byte or character CNN|under 1M|under 1 MB|Payload classifier on first N bytes|
|BERT-tiny|~4M|~4 MB|Small text or log classifier|
|MobileBERT|~25M|~25 MB|Slow-lane triage|
|DistilBERT|~66M|~65 MB|Slow-lane triage (heavier)|



A small generative model that writes decent alert text needs roughly 100M or more parameters, which is hundreds of MB. 

### What makes it different 

Snort, Suricata, Zeek, CrowdSec, OpenSnitch and Windows Defender Firewall already cover much of the detection, and ML intrusion detection is heavily published. The gap is packaging: 

- Plain-language alerts for non-experts. 

- Per-device learned baselines that never leave the machine. 

- Allow/block feedback that improves the local model. 

- A tiny footprint, for example a Raspberry Pi guarding a home network of IoT devices. 

### Safety defaults 

Always allow loopback, DHCP and DNS. Default to fail-open so a bug cannot lock the owner out. Develop and test inside a VM. 

## Key features and MVP 

The hackathon MVP is rules, a scan and flood detector and one flow-based ML model that block live traffic and explain themselves; everything else is a stretch goal. 

|Feature|MVP|What it does|
|---|---|---|
|Packet capture and block|Yes|Intercepts inbound packets on the host and<br>drops flagged ones|
|Blocklist and reputation<br>check|Yes|Bloom filter of known-bad IPs and domains|



Page 3 of 10 

Local Adaptive Firewall: Project Proposal 

|Feature|MVP|What it does|
|---|---|---|
|Signature and protocol<br>checks|Yes|Pattern matching and malformed-packet rules|
|Port-scan and flood<br>detection|Yes|Rate and fan-out rules per source|
|Flow-based ML classifier|Yes|Random Forest or LightGBM on flow features|
|Plain-language OS alert|Yes|What was blocked, why, and an "allow once"<br>button|
|Local event log|Yes|Searchable history with evidence per block|
|Passive source intelligence|Yes|WHOIS/RDAP, ASN, GeoIP and reputation<br>lookups in the alert|
|Honeypot decoy port|Stretch|Any touch on a fake service is flagged and<br>blocked|
|Per-process attribution|Stretch|Ties connections to the owning application|
|Anomaly autoencoder|Stretch|Learns the machine's normal traffic|
|Evidence export|Stretch|Bundle with timestamps, summaries and hashes<br>for abuse reports|
|Slow-lane language model|Stretch|Explains alerts and triages odd events off-path|
|Local feedback learning|Stretch|Allow/block clicks retrain the model on the<br>device|



### MVP demo flow 

1. Start the firewall on a laptop and show normal browsing passing untouched. 

2. From a second machine in the lab, run a port scan against the laptop. 

3. The firewall detects the scan, blocks the source and pops up a system notification naming the reason and the evidence. 

4. Run a flood or brute-force test and show a second alert with a different reason. 

5. Open the log to show each block with its evidence, then click "allow once" to show the override. 

Page 4 of 10 

Local Adaptive Firewall: Project Proposal 

## Technology stack 

Python carries the prototype; a Rust or C data path is the route to real line rate. 

|Layer|Prototype|Production path|
|---|---|---|
|Packet interception|Scapy, NetfilterQueue (Linux),<br>pydivert / WinDivert (Windows)|nftables, eBPF/XDP, WFP;<br>Rust or C data path|
|Flow features|nfstream, Zeek, CICFlowMeter|In-process flow table|
|Detection rules|Python rules, Aho-Corasick library,<br>Bloom filter|Compiled rule engine|
|ML models|scikit-learn, LightGBM|ONNX Runtime, int8<br>quantized|
|Small neural model<br>(optional)|Hugging Face Transformers,<br>PEFT/LoRA on Colab or Kaggle|Distilled, quantized, exported<br>to ONNX|
|Storage|SQLite event log|SQLite or embedded<br>database|
|Alerts and UI|OS notifications (plyer, win10toast,<br>notify-send), small local<br>dashboard (Flask or FastAPI)|Native tray app|
|Source intelligence|WHOIS/RDAP, MaxMind GeoLite2,<br>AbuseIPDB, VirusTotal, GreyNoise,<br>AlienVault OTX (check each<br>service's terms and rate limits)|Cached offline snapshots|
|Test lab|VirtualBox or VMware, Kali Linux<br>attacker VM, an intentionally<br>vulnerable target VM|CI pipeline with replayed<br>capture files|



## Security testing lab: nmap and other tools 

Every active tool runs only against machines the team owns, inside an isolated lab; the firewall never scans or attacks an unknown source address. 

Page 5 of 10 

Local Adaptive Firewall: Project Proposal 

### Rules of engagement 

**Own systems only.** Nmap and similar tools are fine on systems you own or have written permission to test. Probing someone else's machine can fall under unauthorizedaccess provisions such as India's IT Act. This is not legal advice. 

- **No hack-back.** A source address is often not the attacker: VPNs, Tor, proxies and compromised machines hide the real origin, and spoofed sources would point scans at innocent hosts, possibly government ones. Scanning back also tips off the attacker. 

- **Isolation.** Use a host-only or internal network in VirtualBox or VMware with no route to the internet or the campus network. 

**Defensive response only.** Block, rate-limit, tarpit, log and report. Report through the abuse contact from WHOIS, CERT-In or cybercrime.gov.in. 

### Lab layout 

1. **Defender VM or host:** runs the firewall. 

2. **Attacker VM:** Kali Linux with the tools below. 

3. **Target VMs:** intentionally vulnerable machines or apps built for practice, such as Metasploitable and DVWA. 

4. **Capture point:** tcpdump or Wireshark on the lab interface, saving each run as a labelled pcap. 

### Tools and how the project uses them 

|Tool|Role in the project|Example lab use|Firewall should|
|---|---|---|---|
|Nmap|Scan generator<br>and port-scan<br>detector test|Scan the defender VM's<br>lab address with a SYN<br>scan, connect scan,<br>UDP scan and version<br>or OS detection|Flag many ports<br>probed in a short<br>window and block the<br>source|
|Nmap, slow and<br>evasive modes|Tests whether<br>detection survives<br>stealth|Slow timing templates,<br>packet fragmentation<br>and decoy options<br>against the lab host|Still catch low-and-<br>slow scans;<br>reassemble fragments|
|hping3|Crafted-packet<br>and flood tests|Low-rate SYN, ICMP<br>and malformed-flag<br>packets at the lab host|Rate-limit, drop illegal<br>flag combinations|



Page 6 of 10 

Local Adaptive Firewall: Project Proposal 

|Tool|Role in the project|Example lab use|Firewall should|
|---|---|---|---|
|Scapy|Build custom<br>attack traffic and<br>unit tests|Send malformed<br>headers, overlapping<br>fragments and odd<br>option fields|Drop malformed<br>packets with a clear<br>reason|
|Hydra|Brute-force<br>detector test|Repeated logins against<br>a test SSH or FTP<br>account on a target VM|Detect repeated<br>failures and block the<br>source|
|Metasploit<br>Framework|Exploit-traffic<br>samples|Run known exploits<br>against Metasploitable<br>inside the lab only|Match exploit<br>signatures and<br>anomalous payloads|
|sqlmap and<br>Nikto|Web-attack traffic<br>samples|Point at DVWA in the<br>lab|Detect injection<br>patterns and scanner<br>user-agents|
|tcpreplay|Repeatable<br>regression tests|Replay saved attack<br>captures through the<br>firewall|Same verdicts on<br>every run|
|MITRE Caldera<br>or Atomic Red<br>Team|Adversary<br>emulation|Scripted technique<br>chains on lab hosts|Alert on matching<br>behaviours|
|Wireshark,<br>tcpdump, tshark|Evidence and<br>debugging|Inspect what the<br>firewall saw and what it<br>blocked|n/a|
|Zeek, Suricata,<br>Snort|Baselines to<br>compare against|Run alongside to<br>compare alerts and<br>false positives|Match or beat<br>baseline detections|
|p0f|Passive OS<br>fingerprint|Estimate sender OS<br>from TTL, TCP options<br>and window size|Add an approximate<br>OS hint to the alert|



Red-team replay harness (a project feature) 

A Python script launches each scenario from the attacker VM, records a pcap, labels it with the scenario name, then checks whether the firewall raised the expected alert. The same labelled captures feed model training and the evaluation report. 

Page 7 of 10 

Local Adaptive Firewall: Project Proposal 

1. Define scenarios: port scan, slow scan, SYN flood, brute force, web injection, malformed packets, benign browsing. 

2. Run each scenario on a schedule and save its pcap and labels. 

3. Convert captures to flows with nfstream, Zeek or CICFlowMeter. 

4. Compare firewall verdicts with the labels and report recall, false positives and time to block. 

### Passive source intelligence (instead of scanning back) 

Query public data without touching the sender: 

- WHOIS and RDAP for owner and abuse contact; reverse DNS and ASN lookups. GeoIP via MaxMind GeoLite2. 

- Reputation from AbuseIPDB, VirusTotal, GreyNoise and AlienVault OTX, mostly through their APIs. 

The alert can then read, for example, "Source: hosting provider in a named country, reported many times for SSH brute force this week." 

### Honeypot module 

Run a decoy service such as Cowrie or OpenCanary on an otherwise unused port. Any connection to it is unsolicited by definition: record what the source tried, then block it. Never place the honeypot where it could be used to attack others. 

## Model training and fine-tuning 

Start with a classical model and adopt a neural one only if it clearly beats it. 

1. **Define labels.** Start binary (benign or malicious), then add classes: scan, flood, brute force, injection, beaconing. 

2. **Collect data.** 

   - Public datasets: CIC-IDS2017/2018, UNSW-NB15, CIC-IoT-2023. The team's own benign traffic, captured with consent. 

   - Attack traffic from the isolated lab using the replay harness. 

3. **Preprocess.** Convert pcaps to flows with CICFlowMeter, Zeek or nfstream. For a payload model, use the first N bytes as byte tokens. Split train and test by capture session, not randomly, or the test leaks. Handle class imbalance with class weights. Public datasets have known label and generalization problems, so test across datasets. 

Page 8 of 10 

Local Adaptive Firewall: Project Proposal 

4. **Baseline first.** Train Random Forest or LightGBM on flow features. 

5. **Fine-tune the small transformer, if used.** 

   - Hugging Face Transformers on a Colab or Kaggle GPU. 

   - Full fine-tune for BERT-tiny; LoRA through PEFT for larger models. 

   - Typical starting point: learning rate 2e-5 to 5e-5, 3 to 5 epochs. 

6. **Shrink it.** Distil a larger teacher into the small student, quantize to int8, export to ONNX and run with ONNX Runtime. 

7. **Evaluate what matters.** False-positive rate at a fixed recall, per-class precision and recall, held-out lab attacks, latency, and CPU and RAM overhead. 

8. **Close the loop.** Store the user's allow and block clicks locally and retrain periodically. Federated learning across devices is a stretch goal. 

## Expected impact, metrics and risks 

The project aims to give everyday users the kind of explained, local protection that today needs a security professional, and it fits Theme 2 (cyber security) and Theme 3 (ondevice privacy). 

- **Users:** owners of home networks, students on shared campus networks, small shops and clinics that cannot afford a security team. 

- **Privacy:** traffic data and learned baselines stay on the device. 

- **Understanding:** plain-language reasons help people act on alerts instead of dismissing them. 

- **Low-power devices:** a small footprint lets one Raspberry Pi guard a home's IoT devices. **Responsible design:** defensive only, with no hack-back, which also makes the project easier to defend to judges and security professionals. 

### Metrics to measure 

The numbers in the target column are goals to validate, not results. 

|Metric|Target|How measured|
|---|---|---|
|Recall per attack class|High on scans, floods, brute<br>force|Replay harness with labelled<br>captures|



Page 9 of 10 

Local Adaptive Firewall: Project Proposal 

|Metric|Target|How measured|
|---|---|---|
|False-positive rate on<br>normal browsing|Very low at the chosen recall|Hours of benign traffic across<br>several sessions|
|Added latency, rule path|Low single-digit milliseconds at<br>the 99th percentile|Timed packet runs on the<br>demo laptop|
|CPU and RAM overhead|Small enough for a Raspberry Pi<br>class device|Resource monitor during<br>replay|
|Time to block after<br>attack starts|Seconds or less|Timestamps in the harness|
|Alert clarity|Most test users state the<br>reason correctly|Short user test with non-<br>technical volunteers|



### Risks and mitigations 

- **False positives lock the owner out.** Fail-open default, "allow once" button, allowlist for loopback, DHCP and DNS. 

- **Encrypted traffic hides payloads.** Lean on flow behaviour and per-process attribution. **Public datasets generalize poorly.** Mix in lab and own benign data, split by session, test across datasets. 

- **Python is too slow at line rate.** Demo at modest rates and describe the Rust or C path. **Legal exposure.** Lab only, isolated network, own machines, no scanning of unknown sources. 

- **Overselling the LLM.** Present it as an optional off-path explainer, not the detector. 

Page 10 of 10 

