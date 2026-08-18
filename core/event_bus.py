"""
Event Bus - the nervous system of Rupux.

Every tool (Aid Box / Hacks) publishes events here whenever it finds
something noteworthy (open port, weak policy, malicious file signature,
DoS spike, vulnerability, etc). The Live Dashboard and Attack Navigator
subscribe to this bus and react in real time.

Built on a QObject + pyqtSignal so it is thread-safe when tools run
inside TaskManager worker threads (Qt signals are queued across threads
automatically when connected with the default AutoConnection).
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict

from PyQt6.QtCore import QObject, pyqtSignal


@dataclass
class SecurityEvent:
    source: str                 # plugin id, e.g. "aid_box.file_identifier"
    category: str                # "aid_box" | "hacks"
    title: str                   # short human summary
    severity: str = "info"       # "info" | "low" | "medium" | "high" | "critical"
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


class EventBus(QObject):
    event_published = pyqtSignal(object)  # emits a SecurityEvent

    def publish(self, event: SecurityEvent) -> None:
        self.event_published.emit(event)


# Single shared instance used across the whole application
event_bus = EventBus()
