"""Deterministic synthetic traffic producer for demonstrations and testing.

Legitimate TCP traffic is represented as a complete handshake/data/teardown
flow so stateful inspection has meaningful connection context.
"""

from datetime import datetime, timedelta
from dataclasses import replace
import random
from typing import Iterator

from .packet import Packet


class TrafficGenerator:
    def __init__(self, seed: int | None = None) -> None:
        self.random = random.Random(seed)
        self.now = datetime(2026, 1, 1, 12, 0, 0)

    def _packet(self, src: str, dst: str, src_port: int, dst_port: int | None,
                protocol: str = "TCP",
                flags: frozenset[str] = frozenset({"SYN"}), payload: str = "",
                direction: str = "INBOUND", is_attack: bool = False,
                attack_type: str | None = None) -> Packet:
        packet = Packet(self.now, src, dst, src_port, dst_port, protocol, flags,
                        self.random.randint(60, 1400), payload, direction,
                        is_attack, attack_type)
        self.now += timedelta(milliseconds=self.random.randint(10, 100))
        return packet

    def _normal_flow(self) -> list[Packet]:
        client = self.random.choice(["10.0.0.20", "10.0.0.21"])
        server = self.random.choice(["198.51.100.10", "203.0.113.10"])
        service = self.random.choice([80, 443, 53])
        ephemeral = self.random.randint(32768, 60999)
        if service == 53:
            return [
                self._packet(client, server, ephemeral, service, "UDP", frozenset(),
                             "example.edu", "OUTBOUND"),
                self._packet(server, client, service, ephemeral, "UDP", frozenset(),
                             "9.9.9.9", "INBOUND"),
            ]
        packets = [
            self._packet(client, server, ephemeral, service, "TCP", frozenset({"SYN"}),
                         direction="OUTBOUND"),
            self._packet(server, client, service, ephemeral, "TCP", frozenset({"SYN", "ACK"}),
                         direction="INBOUND"),
            self._packet(client, server, ephemeral, service, "TCP", frozenset({"ACK"}),
                         direction="OUTBOUND"),
            self._packet(client, server, ephemeral, service, "TCP", frozenset({"ACK"}),
                         "GET /index.html", "OUTBOUND"),
            self._packet(server, client, service, ephemeral, "TCP", frozenset({"ACK"}),
                         "HTTP/1.1 200 OK", "INBOUND"),
            self._packet(client, server, ephemeral, service, "TCP", frozenset({"FIN", "ACK"}),
                         direction="OUTBOUND"),
            self._packet(server, client, service, ephemeral, "TCP", frozenset({"FIN", "ACK"}),
                         direction="INBOUND"),
        ]
        return packets

    def _attack(self, kind: str, source: str | None = None) -> Packet:
        source = source or self.random.choice(["198.51.100.66", "198.51.100.67", "203.0.113.66"])
        internal = "10.0.0.10"
        attacker_port = self.random.randint(1024, 65535)
        if kind == "port_scan":
            return self._packet(source, internal, attacker_port, self.random.randint(1, 100),
                                "TCP", frozenset({"SYN"}), direction="INBOUND",
                                is_attack=True, attack_type=kind)
        if kind == "syn_flood":
            return self._packet(source, internal, attacker_port, self.random.randint(1024, 65535),
                                "TCP", frozenset({"SYN"}), direction="INBOUND",
                                is_attack=True, attack_type=kind)
        if kind == "ping_flood":
            return self._packet(source, internal, 0, None, "ICMP", frozenset(),
                                direction="INBOUND", is_attack=True, attack_type=kind)
        if kind == "brute_force":
            return self._packet(source, internal, attacker_port, 22, "TCP", frozenset({"SYN"}),
                                direction="INBOUND", is_attack=True, attack_type=kind)
        if kind == "unsolicited_ack":
            return self._packet(source, internal, 80, self.random.randint(40000, 60000),
                                "TCP", frozenset({"ACK"}), direction="INBOUND",
                                is_attack=True, attack_type=kind)
        if kind == "spoofed_syn_ack":
            return self._packet(source, internal, 443, self.random.randint(40000, 60000),
                                "TCP", frozenset({"SYN", "ACK"}), direction="INBOUND",
                                is_attack=True, attack_type=kind)
        if kind == "high_ephemeral":
            return self._packet(source, internal, 443, self.random.randint(49152, 65535),
                                "TCP", frozenset({"ACK"}), direction="INBOUND",
                                is_attack=True, attack_type=kind)
        payload = {"sqli": "DROP TABLE users", "xss": "<script>alert(1)</script>",
                   "path_traversal": "../../etc/passwd"}[kind]
        return self._packet(source, internal, attacker_port, 80, "TCP", frozenset({"SYN"}),
                            payload, "INBOUND", True, kind)

    def packets(self, count: int, attack_ratio: float) -> Iterator[Packet]:
        if count < 0 or not 0 <= attack_ratio <= 1:
            raise ValueError("count must be non-negative and attack_ratio must be between 0 and 1")
        attacks = ["port_scan", "syn_flood", "ping_flood", "brute_force", "sqli", "xss",
                   "path_traversal", "unsolicited_ack", "spoofed_syn_ack", "high_ephemeral"]
        units: list[list[Packet]] = []
        packet_count = 0
        while packet_count < count:
            if self.random.random() < attack_ratio:
                units.append([self._attack(self.random.choice(attacks))])
                packet_count += 1
            else:
                flow = self._normal_flow()
                units.append(flow)
                packet_count += len(flow)
        self.random.shuffle(units)
        generated = [packet for unit in units for packet in unit]
        clock = datetime(2026, 1, 1, 12, 0, 0)
        for packet in generated[:count]:
            packet = replace(packet, timestamp=clock)
            clock += timedelta(milliseconds=self.random.randint(10, 100))
            yield packet

    def demo(self) -> Iterator[Packet]:
        for index, kind in enumerate(["port_scan", "syn_flood", "ping_flood", "brute_force", "sqli", "xss", "path_traversal"]):
            for _ in range(16 if kind in {"port_scan", "syn_flood", "ping_flood"} else 5):
                yield self._attack(kind, f"198.51.100.{100 + index}")
