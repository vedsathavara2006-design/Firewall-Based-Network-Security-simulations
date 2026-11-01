"""Packet data model used by the entirely simulated network."""

from dataclasses import dataclass, field
from datetime import datetime
import ipaddress
from typing import ClassVar


@dataclass(frozen=True)
class Packet:
    """A network packet.  It contains metadata only; no real sockets are used."""

    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    flags: frozenset[str] = field(default_factory=frozenset)
    size: int = 0
    payload: str = ""
    direction: str = "INBOUND"
    is_attack: bool = False
    attack_type: str | None = None

    PROTOCOLS: ClassVar[frozenset[str]] = frozenset({"TCP", "UDP", "ICMP"})
    DIRECTIONS: ClassVar[frozenset[str]] = frozenset({"INBOUND", "OUTBOUND"})
    TCP_FLAGS: ClassVar[frozenset[str]] = frozenset({"SYN", "ACK", "FIN", "RST"})

    def __post_init__(self) -> None:
        protocol = self.protocol.upper()
        direction = self.direction.upper()
        object.__setattr__(self, "protocol", protocol)
        object.__setattr__(self, "direction", direction)
        object.__setattr__(self, "flags", frozenset(flag.upper() for flag in self.flags))
        if protocol not in self.PROTOCOLS:
            raise ValueError(f"Unsupported protocol: {self.protocol}")
        if direction not in self.DIRECTIONS:
            raise ValueError(f"Unsupported direction: {self.direction}")
        try:
            ipaddress.ip_address(self.src_ip)
            ipaddress.ip_address(self.dst_ip)
        except ValueError as exc:
            raise ValueError("Packet source and destination must be valid IP addresses") from exc
        if self.size < 0:
            raise ValueError("Packet size cannot be negative")
        if self.src_port is not None and not 0 <= self.src_port <= 65535:
            raise ValueError("Source port must be between 0 and 65535")
        if self.dst_port is not None and not 0 <= self.dst_port <= 65535:
            raise ValueError("Destination port must be between 0 and 65535")
        if not self.flags.issubset(self.TCP_FLAGS):
            raise ValueError("Unknown TCP flag")

    @property
    def five_tuple(self) -> tuple[str, str, int | None, int | None, str]:
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol)

    @property
    def reverse_five_tuple(self) -> tuple[str, str, int | None, int | None, str]:
        return (self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.protocol)
