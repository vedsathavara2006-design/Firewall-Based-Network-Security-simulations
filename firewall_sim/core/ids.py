"""Signature and threshold-based intrusion detection for simulated packets."""

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta

from .packet import Packet
import ipaddress


@dataclass(frozen=True)
class Alert:
    attack_type: str
    source_ip: str
    reason: str


class IntrusionDetector:
    def __init__(self, settings: dict[str, int]) -> None:
        self.settings = settings
        self.events: dict[str, deque[datetime]] = defaultdict(deque)
        self.port_events: dict[str, deque[tuple[datetime, int]]] = defaultdict(deque)
        self.violations: dict[str, int] = defaultdict(int)
        self.blacklist: dict[str, datetime] = {}

    def _window(self, key: str, now: datetime, seconds: int) -> deque[datetime]:
        values = self.events[key]
        cutoff = now - timedelta(seconds=seconds)
        while values and values[0] < cutoff:
            values.popleft()
        return values

    def _alert(self, kind: str, packet: Packet, reason: str) -> Alert:
        self.violations[packet.src_ip] += 1
        threshold = self.settings.get("blacklist_violation_threshold", 3)
        if self.violations[packet.src_ip] >= threshold:
            expiry = packet.timestamp + timedelta(seconds=self.settings.get("blacklist_duration_seconds", 60))
            self.blacklist[packet.src_ip] = expiry
        return Alert(kind, packet.src_ip, reason)

    @staticmethod
    def _internal(ip: str) -> bool:
        address = ipaddress.ip_address(ip)
        return address in ipaddress.ip_network("192.168.0.0/16") or address in ipaddress.ip_network("10.0.0.0/8")

    def is_blacklisted(self, ip: str, now: datetime) -> bool:
        expiry = self.blacklist.get(ip)
        if expiry and expiry > now:
            return True
        if expiry:
            del self.blacklist[ip]
            self.violations[ip] = 0
        return False

    def inspect(self, packet: Packet) -> list[Alert]:
        alerts: list[Alert] = []
        now = packet.timestamp
        internal = self._internal(packet.src_ip)
        rate = self._window(f"rate:{packet.src_ip}", now, self.settings.get("rate_limit_window_seconds", 10))
        rate.append(now)
        if (not internal and
                len(rate) > self.settings.get("rate_limit_packets", 40)):
            alerts.append(self._alert("rate_limit", packet, "Per-IP sliding-window rate limit exceeded"))
        if packet.protocol == "TCP" and packet.dst_port:
            ports = self.port_events[packet.src_ip]
            cutoff = now - timedelta(seconds=self.settings.get("port_scan_window_seconds", 10))
            while ports and ports[0][0] < cutoff:
                ports.popleft()
            if "SYN" in packet.flags:
                ports.append((now, packet.dst_port))
            if (not internal and "SYN" in packet.flags and "ACK" not in packet.flags and
                    len({port for _, port in ports}) >= self.settings.get("port_scan_unique_ports", 8)):
                alerts.append(self._alert("port_scan", packet, "Many destination ports contacted in a short window"))
            if "SYN" in packet.flags and "ACK" not in packet.flags:
                syns = self._window(f"syn:{packet.src_ip}", now, self.settings.get("syn_flood_window_seconds", 10))
                syns.append(now)
                if (not internal and len(syns) >= self.settings.get("syn_flood_threshold", 15)):
                    alerts.append(self._alert("syn_flood", packet, "Too many SYN packets without ACK"))
            if packet.dst_port in {21, 22} and "SYN" in packet.flags:
                attempts = self._window(f"brute:{packet.src_ip}", now, self.settings.get("brute_force_window_seconds", 20))
                attempts.append(now)
                if (not internal and len(attempts) >= self.settings.get("brute_force_threshold", 5)):
                    alerts.append(self._alert("brute_force", packet, "Repeated authentication connection attempts"))
        if packet.protocol == "ICMP":
            pings = self._window(f"icmp:{packet.src_ip}", now, self.settings.get("icmp_flood_window_seconds", 10))
            pings.append(now)
            if (not internal and len(pings) >= self.settings.get("icmp_flood_threshold", 15)):
                alerts.append(self._alert("icmp_flood", packet, "Too many ICMP packets in a short window"))
        payload = packet.payload.lower()
        signatures = (("sql_injection", "drop table"), ("xss", "<script>"), ("path_traversal", "../../etc/passwd"))
        for kind, keyword in signatures:
            if keyword in payload:
                alerts.append(self._alert(kind, packet, f"Payload signature detected: {keyword}"))
        return alerts
