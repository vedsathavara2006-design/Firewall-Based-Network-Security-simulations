"""Small state table illustrating stateful TCP inspection."""

from dataclasses import dataclass
from datetime import datetime, timedelta

from .packet import Packet


@dataclass
class Connection:
    key: tuple[str, str, int | None, int | None, str]
    state: str
    last_seen: datetime


class ConnectionTracker:
    STATES = {"NEW", "SYN_SENT", "ESTABLISHED", "FIN_WAIT", "CLOSED"}

    def __init__(self, timeout_seconds: int = 30) -> None:
        self.timeout = timedelta(seconds=timeout_seconds)
        self.connections: dict[tuple[str, str, int | None, int | None, str], Connection] = {}

    def cleanup(self, now: datetime) -> None:
        expired = [key for key, conn in self.connections.items() if now - conn.last_seen > self.timeout]
        for key in expired:
            del self.connections[key]

    def inspect(self, packet: Packet) -> tuple[bool, str]:
        self.cleanup(packet.timestamp)
        key = packet.five_tuple
        reverse = packet.reverse_five_tuple
        connection = self.connections.get(key)
        reverse_connection = self.connections.get(reverse)
        if packet.protocol != "TCP":
            if packet.direction == "OUTBOUND":
                self.connections[key] = Connection(key, "ESTABLISHED", packet.timestamp)
                return True, "New non-TCP flow recorded"
            if reverse_connection:
                reverse_connection.last_seen = packet.timestamp
                return True, "Return traffic for established connection"
            return True, "Non-TCP traffic has no TCP connection state"
        if reverse_connection and reverse_connection.state in {"ESTABLISHED", "FIN_WAIT"}:
            reverse_connection.last_seen = packet.timestamp
            if "FIN" in packet.flags:
                reverse_connection.state = "CLOSED"
            return True, "Return traffic for established connection"
        if packet.flags == frozenset({"SYN"}):
            self.connections[key] = Connection(key, "SYN_SENT", packet.timestamp)
            return True, "New TCP SYN recorded"
        if packet.flags == frozenset({"SYN", "ACK"}):
            if reverse_connection and reverse_connection.state == "SYN_SENT":
                reverse_connection.state = "ESTABLISHED"
                reverse_connection.last_seen = packet.timestamp
                return True, "SYN-ACK established connection"
            return False, "Unsolicited TCP SYN-ACK"
        if connection:
            connection.last_seen = packet.timestamp
            if "RST" in packet.flags:
                connection.state = "CLOSED"
            elif "FIN" in packet.flags:
                connection.state = "FIN_WAIT"
            elif connection.state in {"SYN_SENT", "NEW"} and "ACK" in packet.flags:
                connection.state = "ESTABLISHED"
            return connection.state != "CLOSED", f"Existing TCP state: {connection.state}"
        if "ACK" in packet.flags:
            return False, "Unsolicited TCP ACK"
        self.connections[key] = Connection(key, "NEW", packet.timestamp)
        return True, "New TCP flow"
