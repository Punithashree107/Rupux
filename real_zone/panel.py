"""
Real Zone panel: live, real-world security data and learning tools that
go beyond Rupux's local analysis tools. Starts with CVE Lookup; built
as a QTabWidget so future Real Zone features (methodology tracker,
practice target, report builder) can be added as additional tabs
without restructuring anything.
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QFrame, QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget,
    QPlainTextEdit
)
from PyQt6.QtGui import QColor

from core.config import TEXT, MUTED, PANEL_BG, ACCENT, DANGER, WARN
from core.event_bus import SecurityEvent
from core.task_manager import Worker
from core.logger import get_logger
from core.export_utils import export_table_to_csv

from .cve_lookup import search_cves, CveSearchResult, CveEntry
from .practice_target.server import PracticeTarget, DEFAULT_HTTP_PORT, DECOY_PORTS

logger = get_logger("real_zone.cve_lookup")

SEVERITY_COLOR = {
    "CRITICAL": DANGER, "HIGH": DANGER, "MEDIUM": WARN,
    "LOW": MUTED, "UNKNOWN": MUTED, "NOT SCORED": MUTED,
}


class RealZonePanel(QWidget):
    def __init__(self, event_bus):
        super().__init__()
        self.event_bus = event_bus
        self.current_entries = []
        self.practice_target: PracticeTarget = None
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 24, 24, 24)

        title = QLabel("Real Zone")
        title.setStyleSheet(f"font-size: 20px; font-weight: 700; color:{TEXT};")
        subtitle = QLabel("Live, real-world security data — beyond local analysis.")
        subtitle.setStyleSheet(f"color:{MUTED}; margin-bottom: 6px;")
        root.addWidget(title)
        root.addWidget(subtitle)

        tabs = QTabWidget()
        tabs.addTab(self._build_cve_tab(), "CVE Lookup")
        tabs.addTab(self._build_practice_tab(), "Practice Target")
        root.addWidget(tabs, stretch=1)

    def _build_cve_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(4, 16, 4, 4)

        info = QLabel(
            "Search real, published vulnerabilities from the NVD (National Vulnerability "
            "Database) — the same source security professionals use daily. Enter an exact "
            "CVE ID (e.g. CVE-2021-44228) or a keyword (e.g. 'apache log4j')."
        )
        info.setWordWrap(True)
        info.setStyleSheet(f"color:{MUTED}; margin-bottom: 6px;")
        layout.addWidget(info)

        search_row = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("CVE-2021-44228, or a keyword like 'openssh'...")
        self.search_input.returnPressed.connect(self.on_search)
        self.search_btn = QPushButton("Search")
        self.search_btn.clicked.connect(self.on_search)
        search_row.addWidget(self.search_input, stretch=1)
        search_row.addWidget(self.search_btn)
        layout.addLayout(search_row)

        self.status_label = QLabel("No search yet.")
        self.status_label.setStyleSheet(f"color:{MUTED};")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        export_row = QHBoxLayout()
        self.export_btn = QPushButton("Export to CSV")
        self.export_btn.clicked.connect(self.on_export)
        export_row.addWidget(self.export_btn)
        export_row.addStretch(1)
        layout.addLayout(export_row)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["CVE ID", "Severity", "Score", "Published"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.itemSelectionChanged.connect(self.on_row_selected)
        self.table.setStyleSheet(
            f"QTableWidget {{ background:{PANEL_BG}; color:{TEXT}; border-radius:8px; gridline-color:#2a2e3a; }}"
            f"QHeaderView::section {{ background:{PANEL_BG}; color:{MUTED}; border:none; padding:6px; }}"
        )
        layout.addWidget(self.table, stretch=1)

        layout.addWidget(QLabel("Details:"))
        self.detail_box = QPlainTextEdit()
        self.detail_box.setReadOnly(True)
        self.detail_box.setFixedHeight(110)
        self.detail_box.setStyleSheet(f"background:{PANEL_BG}; color:{TEXT}; border-radius:8px; padding:8px;")
        layout.addWidget(self.detail_box)

        return tab

    def on_search(self):
        query = self.search_input.text().strip()
        if not query:
            self.status_label.setText("Enter a CVE ID or keyword first.")
            return

        self.search_btn.setEnabled(False)
        self.search_btn.setText("Searching...")
        self.status_label.setText(f"Searching NVD for '{query}'...")
        self.table.setRowCount(0)
        self.detail_box.setPlainText("")

        self.worker = Worker(search_cves, query)
        self.worker.finished.connect(self.on_result)
        self.worker.error.connect(self.on_error)
        self.worker.start()

    def on_error(self, error_text: str):
        logger.error(f"CVE search failed: {error_text}")
        self.status_label.setText("Something went wrong. See logs for details.")
        self.search_btn.setEnabled(True)
        self.search_btn.setText("Search")

    def on_result(self, result: CveSearchResult):
        self.search_btn.setEnabled(True)
        self.search_btn.setText("Search")

        if result.error and not result.entries:
            self.status_label.setText(f"⚠ {result.error}")
            self.current_entries = []
            return

        self.current_entries = result.entries
        self.status_label.setText(
            f"Found {result.total_results} result(s) for '{result.query}' — showing {len(result.entries)}."
        )

        self.table.setRowCount(len(result.entries))
        for row, entry in enumerate(result.entries):
            self.table.setItem(row, 0, QTableWidgetItem(entry.cve_id))
            sev_item = QTableWidgetItem(entry.severity)
            sev_item.setForeground(QColor(SEVERITY_COLOR.get(entry.severity, MUTED)))
            self.table.setItem(row, 1, sev_item)
            score_text = f"{entry.score} (CVSS v{entry.cvss_version})" if entry.score is not None else "—"
            self.table.setItem(row, 2, QTableWidgetItem(score_text))
            self.table.setItem(row, 3, QTableWidgetItem(entry.published))

        if result.entries:
            self.table.selectRow(0)

        self._maybe_publish_event(result)

    def on_row_selected(self):
        selected = self.table.selectedItems()
        if not selected or not self.current_entries:
            return
        row = selected[0].row()
        if row >= len(self.current_entries):
            return
        entry = self.current_entries[row]
        refs = "\n".join(f"  • {r}" for r in entry.references) if entry.references else "  (none listed)"
        self.detail_box.setPlainText(f"{entry.description}\n\nReferences:\n{refs}")

    def on_export(self):
        path = export_table_to_csv(self, self.table, "cve_search_results.csv")
        if path:
            self.status_label.setText(f"Exported to {path}")

    def _build_practice_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(4, 16, 4, 4)

        info = QLabel(
            "A small local practice server with deliberate misconfigurations — missing "
            "security headers, an exposed fake .env and .git/config, an unauthenticated "
            "admin page, an insecure cookie, permissive CORS, and two decoy TCP services "
            "for port-scan practice. It runs only on 127.0.0.1 (this machine) and is never "
            "reachable from your network or the internet."
        )
        info.setWordWrap(True)
        info.setStyleSheet(f"color:{MUTED}; margin-bottom: 6px;")
        layout.addWidget(info)

        warning = QLabel(
            "⚠ For local practice only. Never port-forward or expose this server externally."
        )
        warning.setStyleSheet(f"color:{WARN}; font-weight: 600; margin-bottom: 6px;")
        layout.addWidget(warning)

        btn_row = QHBoxLayout()
        self.practice_start_btn = QPushButton("Start Practice Target")
        self.practice_start_btn.clicked.connect(self.on_start_practice_target)
        self.practice_stop_btn = QPushButton("Stop")
        self.practice_stop_btn.clicked.connect(self.on_stop_practice_target)
        self.practice_stop_btn.setEnabled(False)
        btn_row.addWidget(self.practice_start_btn)
        btn_row.addWidget(self.practice_stop_btn)
        btn_row.addStretch(1)
        layout.addLayout(btn_row)

        self.practice_status_label = QLabel("Not running.")
        self.practice_status_label.setStyleSheet(f"color:{MUTED};")
        self.practice_status_label.setWordWrap(True)
        layout.addWidget(self.practice_status_label)

        guide_frame = QFrame()
        guide_frame.setStyleSheet(f"background:{PANEL_BG}; border-radius:10px; padding:14px;")
        guide_layout = QVBoxLayout(guide_frame)
        guide_label = QLabel(
            "Once running, try:\n\n"
            "• Web-App Vulnerability Scan → scan the URL shown above\n"
            "• Network Device Scanner → Port Scanner tab → scan 127.0.0.1\n"
            "  (finds the decoy services on ports 2121 and 2323, with banners)\n\n"
            "Then compare what each tool found against the list of deliberate\n"
            "weaknesses described above — that comparison is the actual practice."
        )
        guide_label.setStyleSheet(f"color:{TEXT};")
        guide_label.setWordWrap(True)
        guide_layout.addWidget(guide_label)
        layout.addWidget(guide_frame)

        layout.addStretch(1)
        return tab

    def on_start_practice_target(self):
        if self.practice_target and self.practice_target.running:
            return
        try:
            self.practice_target = PracticeTarget(http_port=DEFAULT_HTTP_PORT)
            url = self.practice_target.start()
        except OSError as e:
            self.practice_status_label.setText(
                f"⚠ Could not start (port {DEFAULT_HTTP_PORT} may already be in use): {e}"
            )
            return

        decoy_list = ", ".join(str(p) for p in DECOY_PORTS)
        self.practice_status_label.setText(
            f"✓ Running at {url}\nDecoy service ports also listening: {decoy_list} (127.0.0.1 only)"
        )
        self.practice_start_btn.setEnabled(False)
        self.practice_stop_btn.setEnabled(True)
        logger.info(f"Practice target started at {url}")

    def on_stop_practice_target(self):
        if self.practice_target:
            self.practice_target.stop()
        self.practice_status_label.setText("Stopped.")
        self.practice_start_btn.setEnabled(True)
        self.practice_stop_btn.setEnabled(False)
        logger.info("Practice target stopped")

    def _maybe_publish_event(self, result: CveSearchResult):
        """Informational only: surfaces on the dashboard when you look up
        something genuinely severe, so Real Zone research shows up as
        part of your broader security activity feed."""
        critical_or_high = [e for e in result.entries if e.severity in ("CRITICAL", "HIGH")]
        if critical_or_high:
            self.event_bus.publish(SecurityEvent(
                source="real_zone.cve_lookup",
                category="real_zone",
                title=f"Researched {len(critical_or_high)} CRITICAL/HIGH CVE(s) for '{result.query}'",
                severity="info",
                details={"query": result.query, "top_cve": critical_or_high[0].cve_id},
            ))
