# Sentinel Edge — Local Adaptive Firewall

A Windows-first, host-level firewall that decides per inbound packet — rules,
reputation feeds, behavioural detectors and one locally-trained ML model, in
the order of ~50 µs per decision, with plain-language alerts, evidence, and an
**"allow once"** override. It runs entirely on the user's machine; **no packet,
flow, feature or loadable model ever leaves the box**.

Built to the *Local Adaptive Firewall — Project Proposal* (see
`Local Adaptive Firewall Project Proposal.md`). The proposal's feature table
(8 MVP + 6 stretch goals) is implemented and verified below.

---

## Feature checklist (proposal §Key features and MVP)

| # | Feature | Tier | Status | Where |
|---|---------|------|--------|-------|
| 1 | Packet capture and block | MVP | ✅ | `sentinel/capture/divert_win.py` (WinDivert), engine verdict → reinject/drop |
| 2 | Blocklist & reputation check | MVP | ✅ | `sentinel/reputation_store.py` — Bloom accelerator + exact/CIDR/domain confirm |
| 3 | Signature & protocol checks | MVP | ✅ | `sentinel/pipeline/{signatures,protocol}.py` + `sentinel/rules/default_rules.yaml` |
| 4 | Port-scan & flood detection | MVP | ✅ | `sentinel/pipeline/behaviour.py` (scan, SYN flood, brute force; conn-rate, per-source rings) |
| 5 | Flow-based ML classifier | MVP | ✅ | `sentinel/ml/` LightGBM (binary + multi-class); runtime `sentinel/pipeline/flow_ml.py` |
| 6 | Plain-language OS alert w/ "allow once" | MVP | ✅ | `sentinel/alerts/templates.py` + `alerts/toast.py` (Windows toasts → plyer → console) |
| 7 | Local searchable event log | MVP | ✅ | `sentinel/storage/event_log.py` (SQLite evidence + intel, query filters) + dashboard search |
| 8 | Passive source intelligence | MVP | ✅ | `sentinel/intel/` — RDAP/whois, ASN, rDNS, GeoIP, AbuseIPDB/VT/GreyNoise/OTX (env-key) |
| 9 | Honeypot decoy ports | Stretch | ✅ | `sentinel/honeypot/decoy.py` — any touch ⇒ block, input into allow-once |
| 10 | Per-process attribution | Stretch | ✅ | `sentinel/attribution/process.py` (psutil; socket ↔ PID ⇄ exe) |
| 11 | Anomaly autoencoder | Stretch | ✅ | `sentinel/ml/autoencoder.py` (denoising NumPy AE) + `pipeline/anomaly.py` |
| 12 | Evidence export | Stretch | ✅ | `sentinel/export/evidence.py`, dashboard `GET /api/export` (hashed zip + manifest) |
| 13 | Slow-lane language model | Stretch | ✅ | `sentinel/explainer/` — template-first, optional Ollama off the packet path |
| 14 | Local feedback learning | Stretch | ✅ | `sentinel/feedback/loop.py` — Allow-once/allowlist clicks trained in, opt-in |

**Install note:** the decision path is deliberately pip-light (stdlib parser:
`sentinel/packets.py`); scapy is used only for lab crafting/replay/honeypot.

---

## Recent fixes (remediation audit)

A comprehensive audit (`plan.md`) identified 16 issues across the ML pipeline,
detection stages, UI, and tooling. All have been resolved:

### Detection pipeline
- **SYN flood false positives** — `_syn_ring` now only counts `SYN && !ACK`
  packets (not all TCP traffic). A minimum volume guard (`≥15` packets,
  `≥0.25s` span) prevents 2-packet rate-spike false blocks.
- **Fragment flood false positives** — `FragmentTracker` now counts
  *fragments*, not accumulated bytes; standard packets >64 bytes no longer
  trigger false drops.
- **ECN handshake drops** — RFC 3168 standard `SYN+ECE+CWR` handshakes are
  now permitted; only partial/evasion combos are flagged.
- **DNS responses ignored** — DNS is now parsed for both `dport == 53`
  (queries) and `sport == 53` (responses), enabling reputation checks on
  inbound DNS replies.

### Flow table & ML features
- **Zero-packet flow bug** — `FlowTable.update()` now calls `row.update(pkt)`
  immediately on new flow creation. Previously 99.7% of training data had
  `total_pkt_count = 0`.
- **Unidirectional keying** — reverse 5-tuple lookup routes response packets
  as backward traffic in the same flow, populating `bwd_pkts`, `bwd_bytes`,
  and all backward statistics.

### ML training & feedback
- **Multi-class support** — training now produces per-class
  precision/recall/confusion for `benign`, `scan`, `flood`, `bruteforce`,
  `injection`, `beaconing` alongside the binary gating model.
- **Session split fallback** — `session_split()` automatically falls back to
  stratified random split when holdout yields <30 rows or <2 classes.
- **`run_training_from_csvs()`** — implemented the function that
  `feedback/loop.py` imports, resolving the `ImportError` on retrain.
- **Autoencoder multi-CSV crash** — replaced `np.stack` with `np.vstack` for
  varying-length frames and added `np.nan_to_num` sanitization.

### Service lifecycle & UI
- **State loss on `load_model()`** — uses `engine.set_ml_model()` to hot-swap
  the ML model without re-creating the engine (preserves `allow_once` entries,
  runtime blocklists, and subscribers).
- **SQLite file locks** — `stop()` now closes all SQLite connections
  (`event_log`, `intel_cache`, `feedback`), preventing `WinError 32`.
- **Dashboard 404 on CSS** — `StaticFiles` is now mounted on `/static`.
- **URLhaus 410 Gone** — switched from retired `abuse.ch` anonymous download
  to active `curbengh/urlhaus-filter` community mirror.

---

## Quickstart

One-command path (Windows, everything stays inside the project folder):

```bat
setup.bat         :: creates .venv here, installs the pinned requirements into
                  :: it (never global), downloads blocklists, builds harness
                  :: pcaps, trains the LightGBM flow model + anomaly autoencoder
run.bat           :: starts firewall + toasts + decoy honeypot + dashboard
run.bat admin     :: relaunch elevated (UAC) to enable real packet blocking
clean.bat         :: removes .venv + all data\ artifacts; source code stays
```

Manual equivalent (if you prefer explicit control):

```powershell
# 1. isolated venv inside the project folder (Python 3.11+)
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt

# 2. pull live public blocklists -> data/blocklists/reputation.bin
.venv\Scripts\python tools\update_blocklists.py   # FireHOL level1 + Spamhaus DROP
                                                  # + DShield + urlhaus-filter

# 3. train both models from harness captures (or see lab-setup for real datasets)
.venv\Scripts\python -m harness.runner --mode build
.venv\Scripts\python tools\pcap_to_flows.py data\harness\pcaps\benign_browsing.pcap data\harness\pcaps\brute_force.pcap data\harness\pcaps\malformed_packets.pcap data\harness\pcaps\port_scan.pcap data\harness\pcaps\slow_scan.pcap data\harness\pcaps\syn_flood.pcap data\harness\pcaps\web_injection.pcap --label auto --out data\flows\flows.csv
.venv\Scripts\python -m sentinel.main train --csv data\flows\flows.csv          # -> data/models/flow_lgbm.joblib
.venv\Scripts\python -m sentinel.ml.train_anomaly --csv data\flows\flows.csv    # -> data/models/flow_ae.npz

# 4. dry-run the detectors offline (no admin needed)
.venv\Scripts\python -m sentinel.main simulate --scenario scan|flood|signatures|badflags|bruteforce

# 5. dashboard only (no enforcement; observe events from simulate/replay)
.venv\Scripts\python -m sentinel.main dashboard

# 6. full protection — DOES need Administrator (packet filter driver)
.venv\Scripts\python -m sentinel.main serve             # engine + toasts + decoys + dashboard
```

Admin is only required for **blocking** mode. Without it `serve` logs
`FAIL-OPEN: observe-only mode` and the dashboard/health endpoint reports
`enforcement_active: false` — the machine is never locked out.

## Measured performance (this repo, Lenovo-class laptop, CPython 3.11)

| Path | Measured | Proposal target |
|------|----------|-----------------|
| Full decision (parse + 4 detector stages, p99) | **0.04 ms** | single-digit ms ✅ |
| ML inference (LightGBM booster, 1 row, p99) | **0.17 ms** | < 1 ms ✅ |
| Reputation lookup (Bloom + bisect confirm, p50) | 0.037 ms | fast ✅ |
| Harness replay: detection rate / false positives | **100 % / 0** | — |
| Median time-to-block (scan → first drop) | **0.73 s** | seconds ✅ |

## The demo flow (proposal §MVP demo flow)

1. `python -m sentinel.main serve` **as Administrator** — normal browsing
   passes untouched (safety stage always allows loopback/DNS/DHCP).
2. From the lab VM: `nmap -Pn -sV --max-rate 30 <host>` → within ~1.3 s the
   source is blocked ("Port scan detected: 20 distinct ports probed…") and a
   Windows toast names the reason + "Allow once".
3. `hping3 -S -p 80 --flood --rand-source <host>` or `--rate 100` →
   "SYN flood … SYNs/s towards …" alert; `python -m sentinel.main simulate
   flood` replays the same thing locally if there is no second machine.
4. Open `http://127.0.0.1:8636` → searchable log with per-event evidence,
   intel side-card (ASN/GeoIP/abuse score), details, single-click
   **allow once** / **export evidence** zip.
5. Decoy ports (2323, 23, 8081, 8888) touched from the lab VM ⇒ instant
   block alert "Honeypot …".

## Safety contract (proposal §Safety and ethics — enforced in code)

* **Always allow:** loopback, DHCP, DNS (engine stage, not just the capture
  filter — the invariant holds even if the filter changes).
* **Never block your own networks:** `trusted_subnets` (RFC1918 + TEST-NET)
  are exempt from reputation scoring.
* **Fail-open at every layer:** stage exception ⇒ pass; watchdog stall ⇒
  handle closed ⇒ WinDivert auto-reinjects; driver start failure ⇒
  observe-only mode; ML/model errors ⇒ never block on absence of data.
* **Defensive-only:** block / rate-limit / log / report. No hack-back, no
  outbound tampering. Evidence export is plain data (hashes + JSON), for
  abuse reports only.
* **Data locality:** everything (events, intel cache, models, feedback) lives
  in `data/`; the LLM explainer runs off-path and only when you point it at a
  local Ollama.
* **Graceful shutdown:** `stop()` closes all SQLite handles to prevent
  `WinError 32` file locks during testing or cleanup.

## Project layout

```
sentinel/
  packets.py             stdlib IPv4/TCP/UDP/ICMP/DNS parser (hot path; parses
                         both DNS queries and responses for reputation checks)
  bloom.py, reputation_store.py
  config.py              one dataclass config, all 15 sections incl. safety
  pipeline/
    engine.py            DecisionEngine: fusion, safety, allow-once, fail-open,
                         hot-swappable ML model via set_ml_model()
    reputation.py signatures.py protocol.py behaviour.py flow_ml.py anomaly.py
  capture/               win-divert (block) | passive | replay drivers
  ml/
    train.py             LightGBM train (binary + multi-class), session split
                         w/ stratified fallback, run_training_from_csvs()
    autoencoder.py       numpy denoising AE (np.vstack for multi-CSV support)
    datasets.py          CIC-IDS2017/2018 column mapper
  flows/
    flow_table.py        bidirectional flow matching (fwd + rev 5-tuple lookup)
    features.py          THE feature contract (48 cols; parity by construction)
  storage/event_log.py   SQLite events + user actions (searchable evidence)
  alerts/, intel/, attribution/, honeypot/, explainer/, export/, feedback/
  ui/                    FastAPI dashboard + static frontend (localhost:8636)
tools/                   update_blocklists.py, pcap_to_flows.py
harness/runner.py        build/replay/lab evaluation pcaps
tests/                   test_engine.py, test_anomaly.py, test_reputation.py,
                         test_ui_security.py
data/                    blocklists/, models/, flows/, logs/, evidence/, exports/
docs/                    architecture.md, lab-setup.md
```

## Tests & verification

```
python tests\test_engine.py        # engine fusion, safety, allow-once, fail-open …
python tests\test_anomaly.py       # autoencoder fit/threshold/roundtrip + stage wiring
python tests\test_reputation.py    # bloom/CIDR/domain + persistence semantics
python tests\test_ui_security.py   # dashboard DNS-rebinding, CORS, CSWSH guards
python -m harness.runner --mode replay   # detection 100 %, 0 FP, med. TTB 0.73 s
```

See `docs/architecture.md` for design details and `docs/lab-setup.md` for a
real two-machine attack/replay walkthrough (nmap, hping3, hydra + the CIC-IDS
dataset training recipe).
