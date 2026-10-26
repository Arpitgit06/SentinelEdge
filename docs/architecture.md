# Architecture — Sentinel Edge

## Design forces

The proposal's constraints shape everything:

* **First, do no harm.** Fail-open on errors, close on stalls, always-allow
  DNS/DHCP/loopback, owner networks exempt from reputation.
* **Explain every block in plain language** — reason + evidence travel with
  every verdict, into logs, toasts, dashboard and evidence bundles.
* **All local.** No packet/feature leaves the machine; the LLM (if used)
  runs off the packet path against a local endpoint.
* **One feature definition.** Testing tools, training and the runtime share
  `sentinel/flows/features.py::FEATURES` (48 columns including 3 per-source
  context features), so feature-drift bugs are impossible by construction.

## Decision pipeline

```
inbound packet ──► driver (WinDivert) ──► stdlib parse ──► DecisionEngine
                                                          │
   ┌──────────────────────────────────────────────────────┤ stage order
   │ 0 safety   loopback / DHCP / DNS → always allow, exit early
   │ 1 allow-once owner override table (TTL), runtime blocklist (honeypot, feedback)
   │ 2 reputation  Bloom accelerator (+ exact set / sorted CIDR bisect / domains)
   │               trusted_subnets (RFC1918, TEST-NET) exempt before scoring
   │ 3 signatures  YAML rules, Aho-Corasick payload patterns, header predicates
   │ 4 protocol    TCP flag abuse (SYN+FIN, SYN+URG+PSH, CWE), fragment reassembly,
   │               lens/length sanity
   │ 5 behaviour   per-source rings: port-scan fan-out, SYN flood rate, brute-force
   │               attempts on login ports, generic connection-rate
   │ 6 flow ML     LightGBM P(malicious) per flow closure cadence (see below)
   │ 7 anomaly     denoising autoencoder reconstruction error vs benign baseline
   │               (alert-only by default: novelty never auto-blocks)
   └──────────────► verdict fusion → subscribe (log → toasts → dashboard →
                      intel enrichment → honeypot/feedback hooks) → reinject|drop
```

Fusion is explicit: the first stage returning `block` wins, with its reason and
evidence; `allow` from safety and allow-once short-circuit everything. Any
stage exception is swallowed by the engine (`stats["errors_fail_open"]`),
which keeps the packet flowing — correctness bugs must never block the owner.

### Not reinjecting = dropping

WinDivert holds the packet until the driver calls `reinject()`; a verdict of
`block` simply skips the reinject. **Fail-open watchdog:** if the engine
thread stops advancing for `safety.watchdog_timeout_s` (20 s), the driver
closes the handle — the OS re-injects everything held — so a wedged
decision path degrades to *nothing is blocked* rather than *nothing passes*.

A second fail-open layer lives at **driver start**: WinDivert needs the
service to run elevated (WinError 5 otherwise). `FirewallService.start()`
treats that as an expected condition: it logs `FAIL-OPEN: observe-only`,
halts at the safety stage, and the dashboard's `/api/health` reports
`enforcement_active:false` with the reason instead of crashing.

*Engineering note:* pydivert bundles **WinDivert 1.4**, whose filter grammar
has **no unary NOT** — `!loopback` or `!(...)` inside the capture filter makes
`WinDivertOpen` fail with `WinError 87` regardless of elevation. The driver
filter therefore uses only `!=` conjunctions, and the DNS/DHCP bypass is
phrased as `(udp.SrcPort != 53 and …)` behind `(tcp or udp or icmp)`, which
is correct whether or not `udp.*` fields are meaningful for TCP packets.

## Reputation store

`data/blocklists/reputation.bin` is rebuilt from live feeds by
`tools/update_blocklists.py` (FireHOL level1 ≈ 4.6k + Spamhaus DROP ≈ 1.7k +
DShield netsets ≈ 6.3k CIDRs at last run). Lookup is two-plane:

1. **Bloom filter (2 MB, k=7)** answers "maybe known-bad?" in ~5 µs. It is a
   pure accelerator, *never the gate* — exact-IP membership is confirmed
   against the backing set and CIDR ranges via sorted-array bisect, so the
   store cannot false-positive-block. 0.037 ms p50 measured through the full
   ask-and-confirm path.
2. **trusted_subnets** (RFC1918, TEST-NET, loopback) short-circuit to allow —
   a bogon-listed LAN range must never block the owner's own network.

## Flow ML (stage 6)

* **Training:** `tools/pcap_to_flows.py` replays labelled pcaps through the
  *runtime* `FlowTable`, then `sentinel/ml/train.py` fits LightGBM with
  session-based split, class weighting and an `fpr_at_recall` guarantee check;
  the joblib bundle carries the estimator + feature contract + metrics.
  Public-dataset path: CIC-IDS2017/2018 alias loader and UNSW-NB15 CSV loader
  (`sentinel/ml/datasets.py`) produce the same feature matrix.
* **Runtime:** flows in `FlowTable` (same structure the behaviour stage uses)
  infer every 4 packets after a 6-packet minimum; scores ≥ 0.9 block, ≥ 0.6
  quarantine (alert, flow kept), else pass with score-as-evidence.
* **Latency:** the sklearn wrapper's per-call validation rounds to ~2.2 ms;
  the runtime instead calls the raw `booster.predict(..., num_threads=1)` —
  0.05 ms p50 / 0.17 ms p99, identical probabilities (bit-exact, verified).
* **ONNX:** `tools/export_onnx.py` can emit a quantized model;
  `FlowModel` detects `.onnx` and serves through onnxruntime unchanged.

## Anomaly autoencoder (stage 7, stretch)

`sentinel/ml/autoencoder.py` is a 48→32→12→32→48 tanh stack with a **linear
output** (z-scores exceed ±1 — a tanh output layer could never reconstruct),
standardized inputs **clipped to ±8** (heavy-tailed counters would otherwise
let one benign outlier dominate the loss), trained as a **denoising AE**
(σ=0.05 input jitter on standardized space + weight decay) so the threshold
generalizes to unseen benign rows instead of memorizing train rows, and
calibrated at the **97th percentile × 3 margin** of benign reconstruction
error. Measured on this repo's harness corpus: benign 0/159 flagged,
scan 95 %, flood 99 %, brute-force 63 % (brute-force flows genuinely resemble
legitimate small TCP sessions — its unique signal is the per-source context
features the supervised model exploits). The stage runs on the flow cadence
and is **alert-only by default**; `anomaly.alert_only=False` requires ≥
`block_factor×` baseline error to block.

## Intel (slow lane)

Per verdict, enrichment runs on a background thread: RDAP/whois (ipwhois →
rdap.org fallback), rDNS, GeoIP (GeoLite2 if present, ip-api.com otherwise),
p0f-style OS hint from the packet's IP/TTL/window, plus AbuseIPDB /
VirusTotal / GreyNoise / AlienVault-OTX when the respective env keys exist.
Results merge into the event row and refresh dashboard cards; TTL cache
(SQLite, 12 h) keeps repeats cheap.

## Alerts & UI

`build_alert_text()` writes the plain-language message from the verdict's
stage/reason/evidence/intel (template-first); the toast carries an
**Allow once** button on Windows (windows-toasts, plyer fallback, console
prompt last) which loops back into `engine.allow_once.grant(ip, ttl)`.
The dashboard (FastAPI, 127.0.0.1:8636) streams live verdicts over WS and
offers history search (`action/src/dst/stage/q`), per-event detail with
evidence + intel, allow once / allowlist actions, stats, health (incl.
enforcement state), evidence-zip export and the feedback/training status.

## Storage

SQLite `data/logs/events.db` — `events(id, ts, iso, action, stage, src, dst,
src_port, dst_port, proto, reason, plain, score, packet_hash, packet_len,
evidence json, intel json, meta json [+ packet_hex])` and `user_actions(id,
ts, action, target, ttl_s)`. Every block/quarantine stores the packet SHA-256
and (config) the raw hex, so evidence zips are self-sufficient.

## Honeypot & feedback

Decoy ports (default 2323, 23, 8081, 8888; `0`-enabled flags per port) listen
on all interfaces; any handshake alerts **and blocks** via the runtime
blocklist, then the attribution module names the attacking process if local.
Owner clicks (toast/button/API) feed `user_actions` + the FeedbackStore;
`sentinel/feedback/loop.py` re-trains the flow model on-device — strictly
opt-in (`config.feedback.enabled`) with a minimum-clicks guard.
