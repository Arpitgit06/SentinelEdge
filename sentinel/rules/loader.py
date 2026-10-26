"""Rule loader for the signature stage.

Rules follow a compact Suricata/Snort-inspired subset, authored in YAML:

    - id: intraweb.x.y
      action: drop            # drop | alert
      proto: tcp
      dst_port: [80, 443, 8080]
      content: ["UNION SELECT", "wp-admin"]
      case_sensitive: false
      msg: "SQL-injection pattern in HTTP payload"
      severity: high

Payload matching is compiled into a single shared Aho-Corasick automaton for
speed; per-pattern metadata is re-associated at inspection time.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


@dataclass
class PayloadRule:
    rule_id: str
    action: str                          # drop | alert
    proto: str                           # any | tcp | udp | icmp
    dst_ports: Optional[Tuple[int, ...]]  # None = any
    contents: List[str] = field(default_factory=list)
    case_sensitive: bool = False
    msg: str = ""
    severity: str = "medium"

    @property
    def any_port(self) -> bool:
        return self.dst_ports is None


@dataclass
class CompiledRules:
    """Everything the signature stage needs after compilation."""
    automaton: Any = None                # ahocorasick.Automaton or fallback
    fallback_re: List[Tuple[re.Pattern, List[PayloadRule]]] = field(
        default_factory=list)            # used only if pyahocorasick is absent
    counts: Dict[str, int] = field(default_factory=dict)


_P_ROTocols = {"any", "tcp", "udp", "icmp"}


def _ports(raw) -> Optional[Tuple[int, ...]]:                    # type: ignore[no-untyped-def]
    if raw is None or str(raw) == "any":
        return None
    if isinstance(raw, int):
        return (int(raw),)
    if isinstance(raw, (list, tuple)):                 # YAML flow list [80,443]
        return tuple(int(p) for p in raw)
    parts = str(raw).strip("[]()").split(",")
    return tuple(int(p) for p in parts if p.strip())


def load_rules(path: Path) -> List[PayloadRule]:
    """Parse the YAML/JSON rules file -> payload rules (tolerant, ordered)."""
    import json as _json
    text = Path(path).read_text(encoding="utf-8")
    try:
        import yaml                                    # PyYAML optional
        data = yaml.safe_load(text) or []
    except ImportError:
        data = _json.loads(text)                       # JSON fallback
    if isinstance(data, dict):                         # {"rules": [...]} format
        data = data.get("rules", []) or []
    rules: List[PayloadRule] = []
    for entry in data or []:
        if not isinstance(entry, dict):
            continue
        if "content" not in entry and "content_list" not in entry:
            continue
        proto = str(entry.get("proto", "tcp")).lower()
        rules.append(PayloadRule(
            rule_id=str(entry.get("id", f"rule{len(rules)}")),
            action=str(entry.get("action", "drop")).lower(),
            proto=proto if proto in _P_ROTocols else "tcp",
            dst_ports=_ports(entry.get("dst_port")),
            contents=[str(c) for c in
                      (entry.get("content") or entry.get("content_list") or []) if c],
            case_sensitive=bool(entry.get("case_sensitive", False)),
            msg=str(entry.get("msg", "signature match")),
            severity=str(entry.get("severity", "medium")),
        ))
    return rules


def compile_rules(rules: Iterable[PayloadRule]) -> CompiledRules:
    compiled = CompiledRules()
    try:
        import ahocorasick
    except ImportError:
        # Fallback: combined regex per (proto, port-group) — slower but correct.
        by_group: Dict[Tuple[str, Optional[Tuple[int, ...]]], List[PayloadRule]] = {}
        for rule in rules:
            by_group.setdefault((rule.proto, rule.dst_ports), []).append(rule)
        for (proto, ports), group in by_group.items():
            patterns = set()
            for rule in group:
                for content in rule.contents:
                    patterns.add(content if rule.case_sensitive
                                 else content.lower())
            if patterns:
                escaped = [re.escape(p) for p in sorted(patterns, key=len, reverse=True)]
                flags = 0 if any(r.case_sensitive for r in group) else re.IGNORECASE
                compiled.fallback_re.append(
                    (re.compile("|".join(escaped), flags), group))
        compiled.counts = {"rules": len(list(rules)), "automaton": 0}
        return compiled

    automaton = ahocorasick.Automaton()
    # key: (lowercased needle, needle) -> list of rules mentioning that needle
    needle_map: Dict[str, List[PayloadRule]] = {}
    for rule in rules:
        for content in rule.contents:
            key = content if rule.case_sensitive else content.lower()
            needle_map.setdefault(key, []).append(rule)
    needles = sorted(needle_map)         # deterministic build order
    for needle in needles:
        automaton.add_word(needle, (needle, needle_map[needle]))
    automaton.make_automaton()
    compiled.automaton = automaton
    compiled.counts = {"rules": len(list(rules)), "automaton": len(needles)}
    return compiled


def load_compiled(path: Path) -> Tuple[List[PayloadRule], CompiledRules]:
    rules = load_rules(path)
    return rules, compile_rules(rules)
