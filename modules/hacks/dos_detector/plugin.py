"""
Plugin entry point for DoS Attack Detector.
Follows the standard Rupux plugin contract:
  PLUGIN_METADATA dict + get_widget(event_bus) -> QWidget
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFileDialog,
    QFrame, QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget,
    QSpinBox, QLineEdit
)

from core.config import TEXT, MUTED, PANEL_BG, ACCENT, DANGER, WARN
from core.event_bus import SecurityEvent
from core.task_manager import Worker
from core.logger import get_logger
from core.settings import get_setting
from core.export_utils import export_table_to_csv

from .detector import analyze_pcap_file, live_monitor, DosAnalysisResult

logger = get_logger("hacks.dos_detector")

PLUGIN_METADATA = {
    "id": "hacks.dos_detector",
    "name": "DoS Attack Detector",
    "category": "hacks",
    "description": "Analyzes traffic for SYN/ICMP/UDP flood and volumetric denial-of-service patterns.",
    "icon": "alert-triangle",
}

SEVERITY_COLOR = {"critical": DANGER, "high": DANGER, "medium": WARN, "low": MUTED}


class DosDetectorWidget(QWidget):
    def __init__(self, event_bus):
        super().__init__()
        self.event_bus = event_bus
        self.worker = None
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 24, 24, 24)

        title = QLabel("DoS Attack Detector")
        title.setStyleSheet(f"font-size: 20px; font-weight: 700; color:{TEXT};")
        subtitle = QLabel(
            "Analyzes a capture file or live traffic for denial-of-service signatures: "
            "SYN floods, ICMP/UDP floods, and general volumetric spikes from a single source. "
            "This tool only observes traffic — it never generates or sends any."
        )
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet(f"color:{MUTED}; margin-bottom: 10px;")
        root.addWidget(title)
        root.addWidget(subtitle)

        tabs = QTabWidget()
        tabs.addTab(self._build_file_tab(), "Analyze Capture File")
        tabs.addTab(self._build_live_tab(), "Live Monitor")
        root.addWidget(tabs, stretch=1)

        summary_frame = QFrame()
        summary_frame.setStyleSheet(f"background:{PANEL_BG}; border-radius:10px; padding:14px;")
        summary_layout = QVBoxLayout(summary_frame)
        self.summary_label = QLabel("No traffic analyzed yet.")
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
        self.table.setHorizontalHeaderLabels(["Source", "Finding", "Detail"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setStyleSheet(
            f"QTableWidget {{ background:{PANEL_BG}; color:{TEXT}; border-radius:8px; gridline-color:#2a2e3a; }}"
            f"QHeaderView::section {{ background:{PANEL_BG}; color:{MUTED}; border:none; padding:6px; }}"
        )
        root.addWidget(self.table, stretch=1)

    # ---------- Tab 1: file analysis ----------

    def _build_file_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(4, 16, 4, 4)

        row = QHBoxLayout()
        self.file_btn = QPushButton("Choose .pcap / .pcapng File...")
        self.file_btn.clicked.connect(self.on_choose_file)
        self.file_label = QLabel("No file selected.")
        self.file_label.setStyleSheet(f"color:{MUTED};")
        row.addWidget(self.file_btn)
        row.addWidget(self.file_label, stretch=1)
        layout.addLayout(row)
        layout.addStretch(1)
        return tab

    def on_choose_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Choose a capture file", "", "Packet Captures (*.pcap *.pcapng);;All Files (*)"
        )
        if not path:
            return
        self.file_label.setText(path)
        self.status_message("Analyzing capture file for DoS patterns...")
        self.worker = Worker(analyze_pcap_file, path)
        self.worker.finished.connect(self.on_result)
        self.worker.error.connect(self.on_error)
        self.worker.start()

    # ---------- Tab 2: live monitor ----------

    def _build_live_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(4, 16, 4, 4)

        row = QHBoxLayout()
        row.addWidget(QLabel("Duration (seconds):"))
        self.duration_spin = QSpinBox()
        self.duration_spin.setRange(3, 120)
        self.duration_spin.setValue(get_setting("live_capture_default_seconds"))
        row.addWidget(self.duration_spin)

        row.addWidget(QLabel("Interface (optional):"))
        self.iface_input = QLineEdit()
        self.iface_input.setPlaceholderText("leave blank for default")
        row.addWidget(self.iface_input, stretch=1)
        layout.addLayout(row)

        self.live_btn = QPushButton("Start Live Monitoring")
        self.live_btn.clicked.connect(self.on_start_live)
        layout.addWidget(self.live_btn)

        note = QLabel(
            "Note: requires running Rupux as Administrator, plus the Npcap driver "
            "installed (npcap.com) on Windows. On Linux/macOS, run with sudo."
        )
        note.setWordWrap(True)
        note.setStyleSheet(f"color:{MUTED}; font-size: 11px;")
        layout.addWidget(note)
        layout.addStretch(1)
        return tab

    def on_start_live(self):
        self.live_btn.setEnabled(False)
        self.live_btn.setText("Monitoring...")
        self.status_message("Starting live monitor...")

        duration = self.duration_spin.value()
        iface = self.iface_input.text().strip() or None

        self.worker = Worker(live_monitor, duration, iface)
        self.worker.kwargs["progress_callback"] = self.worker.progress.emit
        self.worker.progress.connect(self.status_message)
        self.worker.finished.connect(self.on_live_result)
        self.worker.error.connect(self.on_error)
        self.worker.start()

    def on_live_result(self, result: DosAnalysisResult):
        self.live_btn.setEnabled(True)
        self.live_btn.setText("Start Live Monitoring")
        self.on_result(result)

    # ---------- shared ----------

    def status_message(self, text: str):
        self.summary_label.setText(text)

    def on_error(self, error_text: str):
        logger.error(f"DoS analysis failed: {error_text}")
        self.summary_label.setText("Something went wrong. See logs for details.")
        if hasattr(self, "live_btn"):
            self.live_btn.setEnabled(True)
            self.live_btn.setText("Start Live Monitoring")

    def on_result(self, result: DosAnalysisResult):
        if result.error:
            self.summary_label.setText(f"⚠ {result.error}")
            self.table.setRowCount(0)
            return

        if result.findings:
            self.summary_label.setText(
                f"{result.total_packets} packets over {result.duration_seconds}s — "
                f"⚠ {len(result.findings)} DoS-pattern finding(s) detected."
            )
        else:
            self.summary_label.setText(
                f"{result.total_packets} packets over {result.duration_seconds}s — "
                f"no DoS patterns detected."
            )

        self.table.setRowCount(len(result.findings))
        for row, finding in enumerate(result.findings):
            src_item = QTableWidgetItem(finding.source_ip)
            type_item = QTableWidgetItem(f"{finding.severity.upper()} — {finding.attack_type}")
            detail_item = QTableWidgetItem(finding.detail)
            color = SEVERITY_COLOR.get(finding.severity, MUTED)
            type_item.setForeground(_qcolor(color))
            self.table.setItem(row, 0, src_item)
            self.table.setItem(row, 1, type_item)
            self.table.setItem(row, 2, detail_item)

        self._publish_events(result)

    def on_export(self):
        path = export_table_to_csv(self, self.table, "dos_detection_results.csv")
        if path:
            self.summary_label.setText(f"Exported to {path}")

    def _publish_events(self, result: DosAnalysisResult):
        if result.findings:
            worst = result.findings[0]  # already sorted by severity
            self.event_bus.publish(SecurityEvent(
                source="hacks.dos_detector",
                category="hacks",
                title=f"{len(result.findings)} DoS-pattern finding(s) — worst: {worst.attack_type} from {worst.source_ip}",
                severity=worst.severity,
                details={"finding_count": len(result.findings), "total_packets": result.total_packets},
            ))
        else:
            self.event_bus.publish(SecurityEvent(
                source="hacks.dos_detector",
                category="hacks",
                title=f"Analyzed {result.total_packets} packet(s) — no DoS patterns found",
                severity="info",
                details={"total_packets": result.total_packets},
            ))
        logger.info(f"DoS analysis complete: {len(result.findings)} finding(s)")


def _qcolor(hex_str: str):
    from PyQt6.QtGui import QColor
    return QColor(hex_str)


def get_widget(event_bus):
    return DosDetectorWidget(event_bus)
