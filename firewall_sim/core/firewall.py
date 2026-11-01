"""Firewall pipeline: IDS -> state table -> priority ACL -> event log."""

from collections import Counter
from datetime import datetime
from typing import Any, Iterable

from .connection_tracker import ConnectionTracker
from .ids import Alert, IntrusionDetector
from .logger import EventLogger
from .packet import Packet
from .rule_engine import RuleEngine


class Firewall:
    def __init__(self, engine: RuleEngine, detector: IntrusionDetector,
                 tracker: ConnectionTracker, logger: EventLogger | None = None,
                 stateful: bool = True) -> None:
        self.engine, self.detector, self.tracker = engine, detector, tracker
        self.logger, self.stateful = logger, stateful
        self.records: list[dict[str, Any]] = []
        self.attack_types: Counter[str] = Counter()
        self.blocked_ips: Counter[str] = Counter()
        self.rules: Counter[str] = Counter()

    def process(self, packet: Packet) -> dict[str, Any]:
        alerts = self.detector.inspect(packet)
        for alert in alerts:
            self.attack_types[alert.attack_type] += 1
        if self.detector.is_blacklisted(packet.src_ip, packet.timestamp):
            action, reason, rule_id = "DENY", "Temporary IDS blacklist", "ids-blacklist"
        else:
            state_ok, state_reason = self.tracker.inspect(packet) if self.stateful else (True, "Stateless mode")
            action, rule_reason, rule_id = self.engine.evaluate(packet)
            reason = f"{state_reason}; {rule_reason}"
            if not state_ok:
                action, reason = "DENY", f"{state_reason}; stateful inspection rejected packet"
            elif (state_reason == "Return traffic for established connection" or
                  (packet.direction == "INBOUND" and state_reason == "SYN-ACK established connection") or
                  (packet.direction == "INBOUND" and "ACK" in packet.flags and
                   packet.flags != frozenset({"SYN", "ACK"}))):
                action, rule_id, reason = "ALLOW", "stateful-established", state_reason
        if action in {"DENY", "DROP"}:
            self.blocked_ips[packet.src_ip] += 1
        if rule_id:
            self.rules[rule_id] += 1
        record = {
            "timestamp": packet.timestamp.isoformat(timespec="milliseconds"),
            "event_type": "ALERT" if alerts else "PACKET",
            "src_ip": packet.src_ip, "dst_ip": packet.dst_ip, "protocol": packet.protocol,
            "src_port": packet.src_port, "dst_port": packet.dst_port,
            "flags": ",".join(sorted(packet.flags)),
            "action": action, "rule_id": rule_id, "reason": reason,
            "attack_type": ",".join(alert.attack_type for alert in alerts),
            "alerts": alerts,
            "is_attack": packet.is_attack,
            "ground_truth_attack_type": packet.attack_type,
        }
        self.records.append(record)
        if self.logger:
            self.logger.log(record)
            for alert in alerts:
                self.logger.log({**record, "event_type": "ALERT", "action": "ALERT",
                                 "reason": alert.reason, "attack_type": alert.attack_type})
        return record

    def process_all(self, packets: Iterable[Packet]) -> None:
        for packet in packets:
            self.process(packet)

    def close(self) -> None:
        if self.logger:
            self.logger.close()
