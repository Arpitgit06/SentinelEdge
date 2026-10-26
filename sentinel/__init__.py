"""Sentinel Edge — Local Adaptive Firewall.

A lightweight firewall that lives on the device, inspects inbound traffic
locally, blocks malicious packets in real time, and tells the owner in plain
language what was blocked and why — without sending traffic data off the
machine.

Pipeline (cheap checks first, expensive last, LLM never on the packet path):

    Reputation -> Signatures -> Behaviour -> Flow-ML -> Decision engine

Safety defaults (enforced in code, see sentinel.config.SafetyConfig):
    * Loopback, DHCP and DNS traffic is always allowed.
    * Fail-open: any internal error forwards the packet, never drops.
    * Defensive only: no hack-back, no outbound scanning of unknown sources.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
