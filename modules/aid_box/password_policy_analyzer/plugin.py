"""
Plugin entry point for Password Policy Analyzer.
Follows the standard Rupux plugin contract:
  PLUGIN_METADATA dict + get_widget(event_bus) -> QWidget
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QFrame, QProgressBar, QTableWidget, QTableWidgetItem, QHeaderView,
    QTabWidget
)
from PyQt6.QtCore import Qt

from core.config import TEXT, MUTED, PANEL_BG, ACCENT, DANGER, WARN
from core.event_bus import SecurityEvent
from core.logger import get_logger
from core.export_utils import export_table_to_csv

from .analyzer import analyze_password, get_system_policy

logger = get_logger("aid_box.password_policy_analyzer")

PLUGIN_METADATA = {
    "id": "aid_box.password_policy_analyzer",
    "name": "Password Policy Analyzer",
    "category": "aid_box",
    "description": "Tests password strength and checks your system's account password policy.",
    "icon": "shield-check",
}

SCORE_COLORS = {
    "Very Weak": DANGER, "Weak": DANGER, "Fair": WARN,
    "Strong": ACCENT, "Very Strong": ACCENT,
}


def _score_color(verdict: str) -> str:
    for key, color in SCORE_COLORS.items():
        if verdict.startswith(key):
            return color
    return MUTED


class PasswordPolicyWidget(QWidget):
    def __init__(self, event_bus):
        super().__init__()
        self.event_bus = event_bus
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 24, 24, 24)

        title = QLabel("Password Policy Analyzer")
        title.setStyleSheet(f"font-size: 20px; font-weight: 700; color:{TEXT};")
        subtitle = QLabel(
            "Test individual password strength, or check your machine's own account "
            "password policy against recommended baselines. Passwords typed here are "
            "never stored, logged, or sent anywhere."
        )
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet(f"color:{MUTED}; margin-bottom: 10px;")

        root.addWidget(title)
        root.addWidget(subtitle)

        tabs = QTabWidget()
        tabs.addTab(self._build_tester_tab(), "Password Tester")
        tabs.addTab(self._build_system_tab(), "System Policy")
        root.addWidget(tabs, stretch=1)

    # ---------- Tab 1: password tester ----------

    def _build_tester_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(4, 16, 4, 4)

        input_row = QHBoxLayout()
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Type a password to test...")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.textChanged.connect(self.on_password_changed)

        self.toggle_btn = QPushButton("Show")
        self.toggle_btn.setFixedWidth(60)
        self.toggle_btn.clicked.connect(self.toggle_visibility)

        input_row.addWidget(self.password_input, stretch=1)
        input_row.addWidget(self.toggle_btn)
        layout.addLayout(input_row)

        result_frame = QFrame()
        result_frame.setStyleSheet(f"background:{PANEL_BG}; border-radius:10px; padding:16px;")
        result_layout = QVBoxLayout(result_frame)

        self.verdict_label = QLabel("Enter a password above to see its strength.")
        self.verdict_label.setStyleSheet(f"font-size: 16px; font-weight: 600; color:{TEXT};")

        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 100)
        self.strength_bar.setValue(0)
        self.strength_bar.setTextVisible(False)
        self.strength_bar.setFixedHeight(10)

        self.details_label = QLabel("")
        self.details_label.setStyleSheet(f"color:{MUTED};")
        self.details_label.setWordWrap(True)

        self.checks_label = QLabel("")
        self.checks_label.setStyleSheet(f"color:{TEXT}; margin-top:8px;")
        self.checks_label.setWordWrap(True)

        self.suggestions_label = QLabel("")
        self.suggestions_label.setStyleSheet(f"color:{MUTED}; margin-top:8px;")
        self.suggestions_label.setWordWrap(True)

        result_layout.addWidget(self.verdict_label)
        result_layout.addWidget(self.strength_bar)
        result_layout.addWidget(self.details_label)
        result_layout.addWidget(self.checks_label)
        result_layout.addWidget(self.suggestions_label)

        layout.addWidget(result_frame)
        layout.addStretch(1)
        return tab

    def toggle_visibility(self):
        if self.password_input.echoMode() == QLineEdit.EchoMode.Password:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.toggle_btn.setText("Hide")
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.toggle_btn.setText("Show")

    def on_password_changed(self, text: str):
        analysis = analyze_password(text)

        self.strength_bar.setValue(analysis.score)
        color = _score_color(analysis.verdict)
        self.strength_bar.setStyleSheet(
            f"QProgressBar {{ background:{PANEL_BG}; border-radius:5px; }}"
            f"QProgressBar::chunk {{ background:{color}; border-radius:5px; }}"
        )

        if not text:
            self.verdict_label.setText("Enter a password above to see its strength.")
            self.details_label.setText("")
            self.checks_label.setText("")
            self.suggestions_label.setText("")
            return

        self.verdict_label.setText(f"{analysis.verdict}  ·  Score {analysis.score}/100")
        self.verdict_label.setStyleSheet(f"font-size: 16px; font-weight: 600; color:{color};")
        self.details_label.setText(
            f"Length: {analysis.length} characters   ·   Estimated entropy: {analysis.entropy_bits} bits"
        )

        check_lines = []
        labels = {
            "length_12plus": "12+ characters",
            "has_lowercase": "Lowercase letters",
            "has_uppercase": "Uppercase letters",
            "has_digit": "Numbers",
            "has_special": "Special characters",
            "no_repeated_chars": "No 3+ repeated characters",
        }
        for key, label in labels.items():
            passed = analysis.checks.get(key, False)
            icon = "✓" if passed else "✗"
            check_lines.append(f"{icon} {label}")
        self.checks_label.setText("   ".join(check_lines))

        self.suggestions_label.setText("Suggestions: " + " ".join(analysis.suggestions))

        # Only publish an event for genuinely weak/common passwords -- no need
        # to spam the dashboard every keystroke of an already-strong password.
        if analysis.is_common or analysis.score < 45:
            self.event_bus.publish(SecurityEvent(
                source="aid_box.password_policy_analyzer",
                category="aid_box",
                title="Weak password detected during testing" + (
                    " (matches a common password list)" if analysis.is_common else ""
                ),
                severity="high" if analysis.is_common else "medium",
                details={"score": analysis.score, "verdict": analysis.verdict},
            ))

    # ---------- Tab 2: system policy ----------

    def _build_system_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(4, 16, 4, 4)

        self.sys_check_btn = QPushButton("Check My System's Password Policy")
        self.sys_check_btn.clicked.connect(self.on_check_system_policy)
        layout.addWidget(self.sys_check_btn)

        self.sys_status_label = QLabel("Not checked yet.")
        self.sys_status_label.setStyleSheet(f"color:{MUTED}; margin-top:6px;")
        self.sys_status_label.setWordWrap(True)
        layout.addWidget(self.sys_status_label)

        self.sys_table = QTableWidget(0, 4)
        self.sys_table.setHorizontalHeaderLabels(["Setting", "Current Value", "Recommended", "Status"])
        self.sys_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.sys_table.verticalHeader().setVisible(False)
        self.sys_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.sys_table.setStyleSheet(
            f"QTableWidget {{ background:{PANEL_BG}; color:{TEXT}; border-radius:8px; gridline-color:#2a2e3a; }}"
            f"QHeaderView::section {{ background:{PANEL_BG}; color:{MUTED}; border:none; padding:6px; }}"
        )
        layout.addWidget(self.sys_table, stretch=1)

        export_row = QHBoxLayout()
        self.sys_export_btn = QPushButton("Export to CSV")
        self.sys_export_btn.clicked.connect(self.on_export_system_policy)
        export_row.addWidget(self.sys_export_btn)
        export_row.addStretch(1)
        layout.addLayout(export_row)

        return tab

    def on_export_system_policy(self):
        path = export_table_to_csv(self, self.sys_table, "system_password_policy.csv")
        if path:
            self.sys_status_label.setText(f"Exported to {path}")

    def on_check_system_policy(self):
        result = get_system_policy()

        if result.error:
            self.sys_status_label.setText(result.error)
            self.sys_table.setRowCount(0)
            return

        self.sys_table.setRowCount(len(result.items))
        for row, item in enumerate(result.items):
            self.sys_table.setItem(row, 0, QTableWidgetItem(item.label))
            self.sys_table.setItem(row, 1, QTableWidgetItem(item.current_value))
            self.sys_table.setItem(row, 2, QTableWidgetItem(item.recommended))
            status_item = QTableWidgetItem("✓ OK" if item.passed else "⚠ Weak")
            status_item.setForeground(Qt.GlobalColor.green if item.passed else Qt.GlobalColor.yellow)
            self.sys_table.setItem(row, 3, status_item)

        if result.weak_count > 0:
            self.sys_status_label.setText(
                f"⚠ {result.weak_count} of {len(result.items)} policy setting(s) fall below recommended baseline."
            )
            self.event_bus.publish(SecurityEvent(
                source="aid_box.password_policy_analyzer",
                category="aid_box",
                title=f"System password policy has {result.weak_count} weak setting(s)",
                severity="medium",
                details={"weak_count": result.weak_count, "platform": result.platform},
            ))
        else:
            self.sys_status_label.setText("✓ All checked policy settings meet the recommended baseline.")
            self.event_bus.publish(SecurityEvent(
                source="aid_box.password_policy_analyzer",
                category="aid_box",
                title="System password policy checked — meets baseline",
                severity="info",
                details={"platform": result.platform},
            ))

        logger.info(f"System policy checked: {result.weak_count} weak setting(s)")


def get_widget(event_bus):
    return PasswordPolicyWidget(event_bus)
