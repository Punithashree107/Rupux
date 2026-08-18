"""
Plugin entry point for Web-App Vulnerability Scan.
Follows the standard Rupux plugin contract:
  PLUGIN_METADATA dict + get_widget(event_bus) -> QWidget
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QFrame, QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt6.QtGui import QColor

from core.config import TEXT, MUTED, PANEL_BG, ACCENT, DANGER, WARN
from core.event_bus import SecurityEvent
from core.task_manager import Worker
from core.logger import get_logger
from core.export_utils import export_table_to_csv

from .scanner import scan_target, WebScanResult

logger = get_logger("hacks.webapp_vuln_scanner")

PLUGIN_METADATA = {
    "id": "hacks.webapp_vuln_scanner",
    "name": "Web-App Vulnerability Scan",
    "category": "hacks",
    "description": "Passively checks a web app's security headers, cookies, TLS, and common exposed paths.",
    "icon": "globe",
}

SEVERITY_COLOR = {"high": DANGER, "medium": WARN, "low": MUTED, "info": ACCENT}


class WebAppScanWidget(QWidget):
    def __init__(self, event_bus):
        super().__init__()
        self.event_bus = event_bus
        self.worker = None
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 24, 24, 24)

        title = QLabel("Web-App Vulnerability Scan")
        title.setStyleSheet(f"font-size: 20px; font-weight: 700; color:{TEXT};")
        subtitle = QLabel(
            "Passive, non-destructive checks only: security headers, cookie flags, TLS "
            "certificate health, server info disclosure, and common exposed paths. "
            "No injection payloads, no exploitation."
        )
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet(f"color:{MUTED}; margin-bottom: 6px;")
        root.addWidget(title)
        root.addWidget(subtitle)

        warning = QLabel(
            "⚠ Only scan systems you own or have explicit written permission to test. "
            "Scanning third-party systems without authorization is illegal in most jurisdictions."
        )
        warning.setWordWrap(True)
        warning.setStyleSheet(f"color:{WARN}; font-weight: 600; margin-bottom: 10px;")
        root.addWidget(warning)

        input_row = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://your-own-site.example.com")
        self.scan_btn = QPushButton("Scan")
        self.scan_btn.clicked.connect(self.on_scan)
        input_row.addWidget(self.url_input, stretch=1)
        input_row.addWidget(self.scan_btn)
        root.addLayout(input_row)

        summary_frame = QFrame()
        summary_frame.setStyleSheet(f"background:{PANEL_BG}; border-radius:10px; padding:14px;")
        summary_layout = QVBoxLayout(summary_frame)
        self.summary_label = QLabel("No scan run yet.")
        self.summary_label.setStyleSheet(f"color:{MUTED};")
        self.summary_label.setWordWrap(True)
        summary_layout.addWidget(self.summary_label)
        root.addWidget(summary_frame)

        export_row = QHBoxLayout()
        self.export_btn = QPushButton("Export to CSV")
        self.export_btn.clicked.connect(self.on_export)
        export_row.addWidget(self.export_btn)
        export_row.addStretch(1)
        root.addLayout(export_row)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Severity / Category", "Finding", "Detail"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setStyleSheet(
            f"QTableWidget {{ background:{PANEL_BG}; color:{TEXT}; border-radius:8px; gridline-color:#2a2e3a; }}"
            f"QHeaderView::section {{ background:{PANEL_BG}; color:{MUTED}; border:none; padding:6px; }}"
        )
        root.addWidget(self.table, stretch=1)

    def on_scan(self):
        url = self.url_input.text().strip()
        if not url:
            self.summary_label.setText("Enter a URL first.")
            return

        self.scan_btn.setEnabled(False)
        self.scan_btn.setText("Scanning...")
        self.table.setRowCount(0)
        self.summary_label.setText("Starting scan...")

        self.worker = Worker(scan_target, url)
        self.worker.kwargs["progress_callback"] = self.worker.progress.emit
        self.worker.progress.connect(self.on_progress)
        self.worker.finished.connect(self.on_result)
        self.worker.error.connect(self.on_error)
        self.worker.start()

    def on_progress(self, message: str):
        self.summary_label.setText(message)

    def on_error(self, error_text: str):
        logger.error(f"Web scan failed: {error_text}")
        self.summary_label.setText("Something went wrong. See logs for details.")
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("Scan")

    def on_result(self, result: WebScanResult):
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("Scan")

        if result.error:
            self.summary_label.setText(f"⚠ {result.error}")
            return

        high_count = sum(1 for f in result.findings if f.severity == "high")
        med_count = sum(1 for f in result.findings if f.severity == "medium")
        self.summary_label.setText(
            f"Scanned {result.final_url} (HTTP {result.status_code}) — "
            f"{len(result.findings)} finding(s): {high_count} high, {med_count} medium."
        )

        self.table.setRowCount(len(result.findings))
        for row, f in enumerate(result.findings):
            sev_item = QTableWidgetItem(f"{f.severity.upper()} — {f.category}")
            sev_item.setForeground(QColor(SEVERITY_COLOR.get(f.severity, MUTED)))
            self.table.setItem(row, 0, sev_item)
            self.table.setItem(row, 1, QTableWidgetItem(f.title))
            self.table.setItem(row, 2, QTableWidgetItem(f.detail))

        self._publish_events(result)

    def on_export(self):
        path = export_table_to_csv(self, self.table, "webapp_scan_results.csv")
        if path:
            self.summary_label.setText(f"Exported to {path}")

    def _publish_events(self, result: WebScanResult):
        high_findings = [f for f in result.findings if f.severity == "high"]
        if high_findings:
            self.event_bus.publish(SecurityEvent(
                source="hacks.webapp_vuln_scanner",
                category="hacks",
                title=f"{len(high_findings)} high-severity web finding(s) on {result.final_url}",
                severity="high",
                details={"target": result.target, "finding_count": len(result.findings)},
            ))
        else:
            self.event_bus.publish(SecurityEvent(
                source="hacks.webapp_vuln_scanner",
                category="hacks",
                title=f"Web scan complete on {result.final_url} — no high-severity findings",
                severity="info",
                details={"target": result.target, "finding_count": len(result.findings)},
            ))
        logger.info(f"Web scan complete: {len(result.findings)} finding(s)")


def get_widget(event_bus):
    return WebAppScanWidget(event_bus)
