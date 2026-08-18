"""
LIVE DASHBOARD
--------------
The home screen of Rupux. Subscribes to the shared event_bus and shows,
in real time:
  - a running risk score for the current session
  - a live alert/activity feed from every tool that has been run
  - a small severity breakdown

It does not know anything about individual tools -- it only reacts to
SecurityEvent objects, so any new plugin automatically shows up here
the moment it publishes an event. No wiring needed per tool.
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QListWidget,
    QListWidgetItem, QFrame, QSplitter
)
from PyQt6.QtCore import Qt

from core.event_bus import event_bus, SecurityEvent
from core.config import DANGER, WARN, ACCENT, MUTED, TEXT, PANEL_BG

SEVERITY_WEIGHT = {"info": 0, "low": 2, "medium": 5, "high": 10, "critical": 20}
SEVERITY_COLOR = {
    "info": ACCENT, "low": ACCENT, "medium": WARN, "high": DANGER, "critical": DANGER
}


class LiveDashboard(QWidget):
    def __init__(self, attack_navigator=None, parent=None):
        super().__init__(parent)
        self.risk_score = 0
        self._event_count = 0
        self.attack_navigator = attack_navigator
        self._build_ui()
        event_bus.event_published.connect(self.on_event)

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 24, 24, 24)

        header = QLabel("Live Security Dashboard")
        header.setStyleSheet(f"font-size: 22px; font-weight: 700; color: {TEXT};")
        root.addWidget(header)

        stats_row = QHBoxLayout()
        self.risk_card = self._stat_card("Risk Score", "0")
        self.events_card = self._stat_card("Events Logged", "0")
        self.status_card = self._stat_card("Status", "Monitoring")
        stats_row.addWidget(self.risk_card)
        stats_row.addWidget(self.events_card)
        stats_row.addWidget(self.status_card)
        root.addLayout(stats_row)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        feed_frame = QFrame()
        feed_layout = QVBoxLayout(feed_frame)
        feed_label = QLabel("Live Activity Feed")
        feed_label.setStyleSheet(f"font-weight: 600; color: {TEXT}; margin-top: 8px;")
        self.feed = QListWidget()
        self.feed.setStyleSheet(f"background:{PANEL_BG}; color:{TEXT}; border-radius:8px;")
        feed_layout.addWidget(feed_label)
        feed_layout.addWidget(self.feed)

        splitter.addWidget(feed_frame)

        if self.attack_navigator is not None:
            splitter.addWidget(self.attack_navigator)
            splitter.setSizes([600, 350])

        root.addWidget(splitter, stretch=1)

    def _stat_card(self, label: str, value: str) -> QFrame:
        card = QFrame()
        card.setStyleSheet(f"background:{PANEL_BG}; border-radius:10px; padding:12px;")
        layout = QVBoxLayout(card)
        val_label = QLabel(value)
        val_label.setStyleSheet(f"font-size: 24px; font-weight: 700; color:{ACCENT};")
        name_label = QLabel(label)
        name_label.setStyleSheet(f"font-size: 12px; color:{MUTED};")
        layout.addWidget(val_label)
        layout.addWidget(name_label)
        card.value_label = val_label
        return card

    def on_event(self, event: SecurityEvent):
        self.risk_score += SEVERITY_WEIGHT.get(event.severity, 0)
        self.risk_card.value_label.setText(str(self.risk_score))

        self._event_count += 1
        self.events_card.value_label.setText(str(self._event_count))

        color = SEVERITY_COLOR.get(event.severity, TEXT)
        ts = event.timestamp.strftime("%H:%M:%S")
        item = QListWidgetItem(f"[{ts}] ({event.severity.upper()}) {event.source}: {event.title}")
        self.feed.insertItem(0, item)

        if self.attack_navigator is not None:
            self.attack_navigator.handle_event(event)
