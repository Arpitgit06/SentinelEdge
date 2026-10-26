"""Configuration for Sentinel Edge.

All knobs live here so behaviour is auditable in one place. Every value has a
safe default: the firewall may never lock its owner out (fail-open), and
loopback/DHCP/DNS are always allowed regardless of config.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _default_data_dir() -> Path:
    env = os.environ.get("SENTINEL_DATA_DIR")
    if env:
        return Path(env)
    return PROJECT_ROOT / "data"


@dataclass
class SafetyConfig:
    """Non-negotiable defaults from the proposal's 'Safety defaults' section."""

    always_allow_loopback: bool = True
    always_allow_dhcp: bool = True          # udp 67/68
    always_allow_dns: bool = True           # udp/tcp 53
    fail_open: bool = True                  # internal error  -> forward, never drop
    defensive_only: bool = True             # never scan/attack an unknown source
    # Packet watchdog: if the capture loop stalls longer than this, close the
    # handle. WinDivert auto-reinjects queued packets when a handle closes,
    # so a stuck engine degrades to "first, do no harm".
    watchdog_timeout_s: float = 20.0


@dataclass
class CaptureConfig:
    driver: str = "win-divert"              # win-divert | passive (Npcap) | replay (pcap)
    windivert_filter: str = (
        # Pre-filter at the capture layer for performance; engine rules below
        # re-enforce the always-allow list in software.
        # NOTE: WinDivert 1.x grammar (bundled with pydivert) has no unary
        # NOT (`!`) — `!loopback` makes WinDivertOpen fail with WinError 87.
        # Loopback is therefore allowed in the engine safety stage instead.
        "inbound and (tcp or udp or icmp)"
    )
    bypass_dns_dhcp_in_filter: bool = True  # exclude udp 53/67/68 at the driver level
    service_name: str = "Sentinel Edge"


@dataclass
class ReputationConfig:
    enabled: bool = True
    bloom_m: int = 1 << 24                  # 16.7M bits ~ 2 MB
    bloom_k: int = 7
    blocklist_dir: Path = _default_data_dir() / "blocklists"
    blocklist_sources: List[str] = field(default_factory=lambda: [
        # Plain-text CIDR / FQDN blocklists (free sources)
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        "https://www.spamhaus.org/drop/drop.txt",
        "https://www.dshield.org/block.txt",
        "https://raw.githubusercontent.com/curbengh/urlhaus-filter/master/urlhaus-filter-domains.txt",
    ])
    refresh_hours: int = 24
    # The owner's own networks are never reputation-blocked (bogon lists
    # include RFC1918; a LAN-facing firewall must not block its owner).
    trusted_subnets: List[str] = field(default_factory=lambda: [
        '127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
        '169.254.0.0/16', '192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24',
    ])


@dataclass
class SignatureConfig:
    enabled: bool = True
    rules_file: Path = PROJECT_ROOT / "sentinel" / "rules" / "default_rules.yaml"


@dataclass
class ProtocolConfig:
    enabled: bool = True
    verify_checksums: bool = False          # off by default: NAT/TSO chb caused FPs
    drop_null_scan: bool = False            # NULL scan is hostile but low risk; alert not drop
    drop_syn_fin: bool = True
    drop_syn_psh: bool = True
    drop_syn_urg_psh: bool = True
    drop_syn_cwe: bool = True
    drop_bad_lengths: bool = True
    reassemble_fragments: bool = True       # catch nmap -f / low-and-slow fragmentation


@dataclass
class BehaviourConfig:
    enabled: bool = True
    # Port scan: N distinct new-connection ports from one source proto within window
    scan_window_s: float = 30.0
    scan_distinct_ports: int = 20           # proposal example: 150 ports in 3 s
    scan_alert_severity: str = "block"
    # SYN flood: SYNs per second per (src -> dst:port) exceeding threshold
    flood_window_s: float = 10.0
    syn_flood_rate: float = 80.0            # SYNs/s towards one service
    icmp_flood_rate: float = 150.0          # ICMP/s from one source
    # Brute force: repeated new-connection attempts at common login services
    bruteforce_window_s: float = 60.0
    bruteforce_attempts: int = 40
    bruteforce_ports: tuple = (21, 22, 23, 25, 110, 143, 445, 1433, 3306, 3389, 5432, 5900)
    # Generic per-source connection rate limit (connections/s)
    conn_rate_limit: float = 120.0


@dataclass
class MLConfig:
    enabled: bool = True
    model_path: Path = _default_data_dir() / "models" / "flow_lgbm.joblib"    # Score thresholds (LightGBM P(malicious)). Quarantine = alert + keep flow,
    # Block = drop like rules-based stages, and the reason explains the score.
    block_threshold: float = 0.90
    quarantine_threshold: float = 0.60
    infer_every_n_packets: int = 4          # inference cadence per flow (flow features)
    min_packets_to_infer: int = 6           # W.A. need a few packets for IAT stats
    fallback_model_path: Path = _default_data_dir() / "models" / "flow_rf.joblib"
    # feedback-learning retraining sources (opt-in; tools/pcap_to_flows.py csvs)
    flow_csvs: List[Path] = field(default_factory=list)


@dataclass
class AnomalyConfig:
    """Stretch goal: autoencoder that learns the machine's normal traffic.

    Unsupervised baseline (benign flows only); flags flows whose
    reconstruction error exceeds a calibrated benign-error percentile.
    Alert-only by default — novelty never auto-blocks unless the owner
    turns on block mode explicitly.
    """
    enabled: bool = True
    model_path: Path = _default_data_dir() / "models" / "flow_ae.npz"
    threshold_percentile: float = 97.0      # calibrated on benign train errors
    alert_only: bool = True                 # quarantine raise, no drop
    block_factor: float = 8.0               # err >= x*baseline when alert_only=False


@dataclass
class StorageConfig:
    event_db: Path = _default_data_dir() / "logs" / "events.db"
    evidence_dir: Path = _default_data_dir() / "evidence"


@dataclass
class AlertConfig:
    enabled: bool = True
    # Which verdicts raise the OS toast (Allow once button attached when allowed)
    toasts_for: tuple = ("block", "quarantine")
    app_id: str = "Sentinel Edge.LocalAdaptiveFirewall"


@dataclass
class DashboardConfig:
    host: str = "127.0.0.1"                 # local-only
    port: int = 8636
    serve_static: bool = True


@dataclass
class IntelConfig:
    enabled: bool = True
    # Free / no-key sources active by default; key-backed APIs (AbuseIPDB,
    # VirusTotal, GreyNoise, AlienVault OTX) activate automatically when the
    # matching env var is present.
    rdap_timeout_s: float = 6.0
    dns_reverse_timeout_s: float = 3.0
    ttl_hours_cache: float = 12.0
    geoip_mmdb: Optional[Path] = None       # optional MaxMind GeoLite2-Country.mmdb
    allow_web_geo_fill: bool = True         # query ip-api.com if no local db
    web_geo_timeout_s: float = 4.0


@dataclass
class HoneypotConfig:
    enabled: bool = False                   # stretch goal; must never be on an in-use port
    ports: tuple = (2323, 23, 8081, 8888)
    bind_host: str = "0.0.0.0"


@dataclass
class AttributionConfig:
    enabled: bool = False                   # stretch goal: needs outbound capture mode
    block_silent_apps: bool = False         # e.g. a text editor must never talk to internet
    silent_apps: tuple = ("notepad.exe", "EXCEL.EXE", "WINWORD.EXE")


@dataclass
class FeedbackConfig:
    enabled: bool = False                   # stretch goal: on-device retraining
    feedback_db: Path = _default_data_dir() / "feedback" / "feedback.db"
    min_events_retrain: int = 100


@dataclass
class SlowLaneConfig:
    enabled: bool = False                   # stretch goal: off-path explainer
    local_model_url: Optional[str] = None   # e.g. http://127.0.0.1:11434 (Ollama)
    model_name: str = "tinyllama"
    timeout_s: float = 8.0


@dataclass
class HarnessConfig:
    """Red-team replay harness (proposal: 'a project feature')."""
    scenarios_dir: Path = PROJECT_ROOT / "harness" / "scenarios"
    pcap_dir: Path = _default_data_dir() / "harness" / "pcaps"
    reports_dir: Path = _default_data_dir() / "harness" / "reports"
    attacker_host: str = ""                 # lab attacker VM; empty = local scapy build


@dataclass
class Config:
    safety: SafetyConfig = field(default_factory=SafetyConfig)
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    reputation: ReputationConfig = field(default_factory=ReputationConfig)
    signatures: SignatureConfig = field(default_factory=SignatureConfig)
    protocol: ProtocolConfig = field(default_factory=ProtocolConfig)
    behaviour: BehaviourConfig = field(default_factory=BehaviourConfig)
    ml: MLConfig = field(default_factory=MLConfig)
    anomaly: AnomalyConfig = field(default_factory=AnomalyConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    alert: AlertConfig = field(default_factory=AlertConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    intel: IntelConfig = field(default_factory=IntelConfig)
    honeypot: HoneypotConfig = field(default_factory=HoneypotConfig)
    attribution: AttributionConfig = field(default_factory=AttributionConfig)
    feedback: FeedbackConfig = field(default_factory=FeedbackConfig)
    slowlane: SlowLaneConfig = field(default_factory=SlowLaneConfig)
    harness: HarnessConfig = field(default_factory=HarnessConfig)
    data_dir: Path = field(default_factory=_default_data_dir)


def load_config(path: Optional[str] = None) -> Config:
    """Load config from YAML/JSON path (optional), else pure defaults.

    Deliberately permissive: unknown keys are ignored so a newer file still
    works with an older engine, and every block has a safe default anyway.
    """
    cfg = Config()
    cfg.data_dir = _default_data_dir()
    if not path:
        return cfg
    import json
    text = Path(path).read_text(encoding="utf-8")
    if path.endswith(".json"):
        overrides = json.loads(text)
    else:
        import yaml  # optional dep; defaults cover absence
        overrides = yaml.safe_load(text) or {}
    for section_name, section in overrides.items():
        target = getattr(cfg, section_name, None)
        if not isinstance(section, dict) or target is None:
            continue
        for key, value in section.items():
            if hasattr(target, key):
                cur = getattr(target, key)
                if isinstance(cur, Path) and isinstance(value, str):
                    value = Path(value)
                setattr(target, key, value)
    return cfg


def ensure_dirs(cfg: Config) -> None:
    """Create runtime directories under the data dir (idempotent)."""
    for sub in ("blocklists", "models", "logs", "evidence", "harness/pcaps",
                "harness/reports", "exports", "feedback", "flows"):
        (cfg.data_dir / sub).mkdir(parents=True, exist_ok=True)


def default_config() -> Config:
    c = Config()
    ensure_dirs(c)
    return c
