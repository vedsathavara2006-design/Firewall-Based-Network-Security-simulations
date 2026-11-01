"""CSV and terminal event logging."""

import csv
from pathlib import Path
from typing import Any

try:
    from rich.console import Console
except ImportError:  # pragma: no cover - requirements installs rich
    Console = Any  # type: ignore[misc,assignment]


class EventLogger:
    def __init__(self, path: str | Path, console: Console | None = None,
                 live: bool = False) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.file = self.path.open("w", newline="", encoding="utf-8")
        self.writer = csv.DictWriter(
            self.file,
            fieldnames=["timestamp", "event_type", "src_ip", "dst_ip", "protocol",
                        "action", "rule_id", "reason", "attack_type"],
            extrasaction="ignore",
        )
        self.writer.writeheader()
        self.console = console
        self.live = live

    def log(self, event: dict[str, Any]) -> None:
        self.writer.writerow(event)
        self.file.flush()
        action = str(event.get("action", event.get("event_type", ""))).upper()
        if self.console is not None:
            if self.live:
                flags = event.get("flags", "-")
                source = f"{event.get('src_ip', '-')}:{event.get('src_port', '-')}"
                target = f"{event.get('dst_ip', '-')}:{event.get('dst_port', '-')}"
                line = (f"[{event.get('timestamp', '-')}] {source} -> {target} | "
                        f"{event.get('protocol', '-')} | {flags} | {action} | "
                        f"{event.get('rule_id') or 'default'} | {event.get('reason', '')}")
            else:
                line = f"{action:<8} {event.get('src_ip', '-'):<15} {event.get('reason', '')}"
            style = "green" if action == "ALLOW" else "red" if action in {"DENY", "DROP"} else "yellow"
            self.console.print(f"[{style}]{line}[/{style}]")

    def close(self) -> None:
        self.file.close()
