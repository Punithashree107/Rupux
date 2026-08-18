"""
ATTACK NAVIGATOR
-----------------
Lives inside the Live Dashboard. It listens to the same event_bus as the
dashboard, but instead of just logging events, it applies simple rules
to turn raw findings into "what to do next" guidance for the user.

This is intentionally rule-based and simple to start with -- it can
later be swapped for a smarter scoring/ML model without touching any
other part of the app, since it only depends on SecurityEvent objects.
"""
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QListWidget, QListWidgetItem
from PyQt6.QtGui import QColor
from core.event_bus import SecurityEvent
from core.config import TEXT, MUTED, PANEL_BG, WARN

# Very small starter rule set: (condition_fn) -> recommendation text
# condition_fn receives the SecurityEvent and returns True/False
RULES = [
    (
        lambda e: e.category == "aid_box" and e.details.get("extension_mismatch"),
        "A file's extension doesn't match its real type. Consider scanning it "
        "with a dedicated malware/AV tool before opening it.",
    ),
    (
        lambda e: e.severity in ("high", "critical"),
        "A high-severity finding was just logged. Review it in the Live "
        "Activity Feed and consider running a deeper scan with Hacks tools.",
    ),
    (
        lambda e: e.source.endswith("network_scanner"),
        "New devices were found on the network. Run Password Policy Analyzer "
        "or Web-App Vulnerability Scan on anything unexpected.",
    ),
]


class AttackNavigator(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        title = QLabel("Attack Navigator")
        title.setStyleSheet(f"font-weight: 600; color: {TEXT}; margin-top: 8px;")
        sub = QLabel("Guidance based on what's happening right now")
        sub.setStyleSheet(f"font-size: 11px; color: {MUTED}; margin-bottom: 6px;")

        self.list = QListWidget()
        self.list.setStyleSheet(f"background:{PANEL_BG}; color:{TEXT}; border-radius:8px;")
        self._placeholder()

        layout.addWidget(title)
        layout.addWidget(sub)
        layout.addWidget(self.list)

    def _placeholder(self):
        item = QListWidgetItem("No recommendations yet. Run a tool from Aid Box or Hacks.")
        self.list.addItem(item)

    def handle_event(self, event: SecurityEvent):
        matched = False
        for condition, recommendation in RULES:
            try:
                if condition(event):
                    self._add_recommendation(recommendation)
                    matched = True
            except Exception:
                continue

        if not matched and self.list.count() == 1 and "No recommendations" in self.list.item(0).text():
            self.list.clear()
            self._add_recommendation(f"Reviewed: {event.title} — no immediate action required.")

    def _add_recommendation(self, text: str):
        if self.list.count() == 1 and "No recommendations" in self.list.item(0).text():
            self.list.clear()
        item = QListWidgetItem(f"→ {text}")
        item.setForeground(QColor(WARN))
        self.list.insertItem(0, item)
