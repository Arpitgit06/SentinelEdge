# Lab setup guide

Two options: a pure-local demo (no second machine) or a proper two-VM lab.

## A. Local demo (no admin required)

Everything except live blocking runs de-privileged — good for a quickdemo:

```powershell
cd D:\Sentinel Edge
python -m sentinel.main simulate --scenario scan       # behaviour detector
python -m sentinel.main simulate --scenario flood      # SYN flood rate detector
python -m sentinel.main simulate --scenario signatures # malicious payload rules
python -m sentinel.main simulate --scenario badflags   # protocol checks
python -m sentinel.main simulate --scenario bruteforce # brute force detector
python -m harness.runner --mode replay                 # all labelled scenarios
# watch the results land:
python -m sentinel.main dashboard      # http://127.0.0.1:8636
```

Each simulate replay prints the per-packet verdicts and the toast/allow-once
pipeline is exercised by the dashboard. Blocks land in
`data/logs/events.db` — searchable in the UI.

## B. Two-VM lab (real attackers)

Host: Windows 10/11 with Npcap (`pip install scapy` uses Npcap for the
passive driver) and WinDivert (bundled via pydivert).

### 1. Run the firewall elevated (blocking mode)

Start an **Administrator** PowerShell in `D:\Sentinel Edge`:

```powershell
python -m sentinel.main serve
```

Expect in the log:

```
reputation store loaded: {...6339 cidr...}
ML model loaded from ... flow_lgbm.joblib
anomaly autoencoder loaded ... (baseline threshold ...)
dashboard on http://127.0.0.1:8636
WinDivert starting with filter: inbound and (tcp or udp or icmp) and (...)
firewall running (win-divert, enforcement=True)
```

Without elevation instead → `FAIL-OPEN: observe-only mode` (see
`docs/architecture.md`). Dashboard keeps working either way.

Configure the attacker VM as `Sentinel Edge cannot be blocked` *trusted
fixture*? **No** — the lab attacker is a normal internet-style host; make sure
its IP is **outside** `trusted_subnets` (RFC1918/TEST-NET are trusted, so use
a 10.x lab net only for the Windows host's own management and source-attack
from a bridged/external network).

### 2. Kali-style attacker commands

From the attacking machine (Kali or any Linux VM with scapy installed):

```bash
# targeted host on the LAN, e.g. 192.168.1.50 (DEFENDER in the harness pcaps)
nmap -Pn -sV --max-rate 30 192.168.1.50          # port scan → ~1.3 s to block
nmap -Pn -sS -f 192.168.1.50                     # fragmented SYN scan
hping3 -S -p 80 --flood --rand-source 192.168.1.50  # SYN flood (rate ~ thousands/s)
hping3 -S -p 22 --rate 120 192.168.1.50          # slow brute force on login port
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.1.50 ssh
telnet 192.168.1.50 2323                          # honeypot decoy touch
```

Expected behaviour: the source is blocked, a Windows toast names the reason and
suggests **Allow once**; clicking it lets that IP through for 300 s (5 min),
and the dashboard event gets `allow_once` recorded in user actions.

### 3. Same attacks without a second VM (scapy all-local)

On the defender host itself (passes the loopback-safety stage — use external
class addresses on an interface, OR run against the passive device...):

```powershell
python -m sentinel.main simulate --scenario flood      # route via loopback
```

The harness already builds every labelled attack as a pcap, so offline is the
easiest scripted route (see A).

## C. Training recipes

### From this repo's harness (fast, deterministic)

```powershell
python -m harness.runner --mode build        # 7 labelled pcaps -> data/pcap
python tools/pcap_to_flows.py --in data/pcap --out data/flows/flows.csv
python -m sentinel.ml.train                  # supervised flow model
python -m sentinel.ml.train_anomaly          # autoencoder baseline (benign only)
```

### From CIC-IDS2017 / CIC-IDS2018 (public datasets; download CSVs yourself)

1. Download e.g. `MachineLearningCSV/Wednesday-workingHours.pcap_ISCX.csv`
   from the CIC website (these are CICFlowMeter exports).
2. Supervised model — header aliases map CICFlowMeter columns onto the
   `FEATURES` contract automatically (`sentinel/ml/datasets.py`):

```powershell
python -m sentinel.main train --cic --csv "C:\data\cic\Wednesday-workingHours.pcap_ISCX.csv" --out data\models\flow_lgbm.joblib
```

3. Anomaly baseline — benign rows are picked out automatically (label
   "BENIGN"):

```powershell
python -m sentinel.ml.train_anomaly --cic --csv "C:\data\cic\benign-heavy-file.csv"
```

Notes: the runtime FlowTable recomputes features exactly as training does
(single `FEATURES` contract), so a LightGBM fitted on the CIC CSVs scores
live flows directly. Session split uses the source CSV as session id, so
prefer giving two or more CSVs from different days for a clean hold-out.
Verify with `python -m harness.runner --mode replay` (expect a solid
detection rate with thresholds tuned in `config.ml.block_threshold`).

## D. Evidence & ops

* **Evidence export** (for an abuse report):
  `curl http://127.0.0.1:8636/api/export?event_id=42 -o evidence.zip` or click
  Export on an event row. Contains the event JSON, intel snapshot, packet
  SHA-256 (+hex) and a manifest.
* **Blocklist refresh**: `python tools/update_blocklists.py` (FireHOL level1,
  Spamhaus DROP, DShield — cron/task-schedüler daily; `refresh_hours` in
  config gates auto-refresh at start).
* **Live health**: `GET /api/health` — `enforcement_active`,
  `enforcement_error`. Harness-quality report:
  `python -m harness.runner --mode lab` (writes data/harness/reports/*.json).

## E. Safety checklist before a public demo

- [ ] `config.safety` flags: always_allow_loopback/DHCP/DNS = True
- [ ] `trusted_subnets` includes the demo LAN → owner never dropped by the
      reputation stage, even if a feed misclassifies
- [ ] Run **as Administrator** only when you actually want blocking; otherwise
      leave non-elevated (observe-only)
- [ ] Watchdog `watchdog_timeout_s` = 20 s (default) — kill the process and
      confirm traffic flows while it's stopped
- [ ] No inbound rules of the host will be mutated — this firewall is a
      packet filter, not the Windows Firewall controller
