"""Priority ACL evaluation using standard CIDR and port matching."""

from dataclasses import dataclass
import ipaddress
import json
from pathlib import Path
from typing import Any

from .packet import Packet


@dataclass(frozen=True)
class Rule:
    id: str
    priority: int
    action: str
    protocol: str | None = None
    src_network: ipaddress._BaseNetwork | None = None
    dst_network: ipaddress._BaseNetwork | None = None
    src_port: tuple[int, int] | None = None
    dst_port: tuple[int, int] | None = None
    direction: str | None = None
    description: str = ""

    @staticmethod
    def _network(value: str | None) -> ipaddress._BaseNetwork | None:
        return ipaddress.ip_network(value, strict=False) if value else None

    @staticmethod
    def _port_range(value: Any) -> tuple[int, int] | None:
        if value is None:
            return None
        if isinstance(value, int):
            result = (value, value)
        elif isinstance(value, str) and "-" in value:
            start, end = value.split("-", 1)
            result = (int(start), int(end))
        else:
            result = (int(value), int(value))
        if not (0 <= result[0] <= result[1] <= 65535):
            raise ValueError(f"Invalid port range: {value}")
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Rule":
        action = str(data["action"]).upper()
        if action not in {"ALLOW", "DENY", "DROP", "LOG"}:
            raise ValueError(f"Invalid rule action: {action}")
        return cls(
            id=str(data["id"]),
            priority=int(data["priority"]),
            action=action,
            protocol=str(data["protocol"]).upper() if data.get("protocol") else None,
            src_network=cls._network(data.get("src_ip")),
            dst_network=cls._network(data.get("dst_ip")),
            src_port=cls._port_range(data.get("src_port")),
            dst_port=cls._port_range(data.get("dst_port")),
            direction=str(data["direction"]).upper() if data.get("direction") else None,
            description=str(data.get("description", "")),
        )

    def matches(self, packet: Packet) -> bool:
        if self.protocol and self.protocol != packet.protocol:
            return False
        if self.direction and self.direction != packet.direction:
            return False
        try:
            if self.src_network and ipaddress.ip_address(packet.src_ip) not in self.src_network:
                return False
            if self.dst_network and ipaddress.ip_address(packet.dst_ip) not in self.dst_network:
                return False
        except ValueError:
            return False
        for expected, actual in ((self.src_port, packet.src_port), (self.dst_port, packet.dst_port)):
            if expected and (actual is None or not expected[0] <= actual <= expected[1]):
                return False
        return True


class RuleEngine:
    """Loads sorted rules and returns the first matching ACL decision."""

    def __init__(self, rules: list[Rule], default_policy: str = "DENY") -> None:
        self.rules = sorted(rules, key=lambda rule: rule.priority)
        self.default_policy = default_policy.upper()
        if self.default_policy not in {"ALLOW", "DENY", "DROP", "LOG"}:
            raise ValueError("Default policy must be ALLOW, DENY, DROP, or LOG")

    @classmethod
    def from_json(cls, path: str | Path, default_policy: str = "DENY") -> "RuleEngine":
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            if not isinstance(data, list):
                raise ValueError("Rules JSON must contain a list")
            return cls([Rule.from_dict(item) for item in data], default_policy)
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"Unable to load firewall rules from {path}: {exc}") from exc

    def evaluate(self, packet: Packet) -> tuple[str, str, str | None]:
        for rule in self.rules:
            if rule.matches(packet):
                return rule.action, rule.description or f"Matched {rule.id}", rule.id
        return self.default_policy, "Default policy", None
