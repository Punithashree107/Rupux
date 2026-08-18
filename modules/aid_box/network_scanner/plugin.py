"""
Plugin entry point for Network Device Scanner.
Follows the standard Rupux plugin contract:
  PLUGIN_METADATA dict + get_widget(event_bus) -> QWidget
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame,
    QTabWidget, QLineEdit, QCheckBox, QComboBox
)
from PyQt6.QtCore import Qt

from core.config import TEXT, MUTED, PANEL_BG, ACCENT, DANGER, WARN
from core.event_bus import SecurityEvent
from core.task_manager import Worker
from core.logger import get_logger
from core.export_utils import export_table_to_csv

from .scanner import scan_network, scan_ports, ScanSummary, PortScanResult, QUICK_SCAN_PORTS

logger = get_logger("aid_box.network_scanner")

PLUGIN_METADATA = {
    "id": "aid_box.network_scanner",
    "name": "Network Device Scanner",
    "category": "aid_box",
    "description": "Discovers devices on your local network and flags any new ones since the last scan.",
    "icon": "wifi",
}


class NetworkScannerWidget(QWidget):
    def __init__(self, event_bus):
        super().__init__()
        self.event_bus = event_bus
        self.worker = None
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 24, 24, 24)

        title = QLabel("Network Device Scanner")
        title.setStyleSheet(f"font-size: 20px; font-weight: 700; color:{TEXT};")
        subtitle = QLabel(
            "Discover devices on your network, and probe a specific host for open ports "
            "— the same TCP connect-scan technique tools like Nmap use."
        )
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet(f"color:{MUTED}; margin-bottom: 10px;")
        root.addWidget(title)
        root.addWidget(subtitle)

        tabs = QTabWidget()
        tabs.addTab(self._build_discovery_tab(), "Network Scan")
        tabs.addTab(self._build_portscan_tab(), "Port Scanner")
        root.addWidget(tabs, stretch=1)

    def _build_discovery_tab(self) -> QWidget:
        tab = QWidget()
        root = QVBoxLayout(tab)
        root.setContentsMargins(4, 16, 4, 4)

        action_row = QHBoxLayout()
        self.scan_btn = QPushButton("Scan Local Network")
        self.scan_btn.clicked.connect(self.on_scan_clicked)
        self.status_label = QLabel("Idle")
        self.status_label.setStyleSheet(f"color:{MUTED};")
        self.export_btn = QPushButton("Export to CSV")
        self.export_btn.clicked.connect(self.on_export)
        action_row.addWidget(self.scan_btn)
        action_row.addWidget(self.export_btn)
        action_row.addWidget(self.status_label, stretch=1)

        summary_frame = QFrame()
        summary_frame.setStyleSheet(f"background:{PANEL_BG}; border-radius:10px; padding:14px;")
        summary_layout = QVBoxLayout(summary_frame)
        self.summary_label = QLabel("No scan run yet.")
        self.summary_label.setStyleSheet(f"color:{MUTED};")
        self.summary_label.setWordWrap(True)
        summary_layout.addWidget(self.summary_label)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["IP Address", "Hostname", "Status"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setStyleSheet(
            f"QTableWidget {{ background:{PANEL_BG}; color:{TEXT}; border-radius:8px; gridline-color:#2a2e3a; }}"
            f"QHeaderView::section {{ background:{PANEL_BG}; color:{MUTED}; border:none; padding:6px; }}"
        )

        root.addLayout(action_row)
        root.addWidget(summary_frame)
        root.addWidget(self.table, stretch=1)
        return tab

    def _build_portscan_tab(self) -> QWidget:
        tab = QWidget()
        root = QVBoxLayout(tab)
        root.setContentsMargins(4, 16, 4, 4)

        warning = QLabel(
            "⚠ Only port-scan hosts you own or have explicit permission to test. "
            "Scanning third-party systems without authorization is illegal in most jurisdictions."
        )
        warning.setWordWrap(True)
        warning.setStyleSheet(f"color:{WARN}; font-weight: 600; margin-bottom: 6px;")
        root.addWidget(warning)

        input_row = QHBoxLayout()
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("IP address or hostname, e.g. 192.168.1.1")
        input_row.addWidget(self.target_input, stretch=1)

        self.scan_mode_combo = QComboBox()
        self.scan_mode_combo.addItems(["Quick Scan (common ports)", "Full Scan (1–1024)"])
        input_row.addWidget(self.scan_mode_combo)

        self.portscan_btn = QPushButton("Scan Ports")
        self.portscan_btn.clicked.connect(self.on_portscan_clicked)
        input_row.addWidget(self.portscan_btn)
        root.addLayout(input_row)

        self.banner_check = QCheckBox("Grab service banners (slightly slower, more informative)")
        self.banner_check.setChecked(True)
        root.addWidget(self.banner_check)

        self.portscan_status_label = QLabel("Idle")
        self.portscan_status_label.setStyleSheet(f"color:{MUTED};")
        self.portscan_status_label.setWordWrap(True)
        root.addWidget(self.portscan_status_label)

        self.portscan_export_btn = QPushButton("Export to CSV")
        self.portscan_export_btn.clicked.connect(self.on_portscan_export)
        root.addWidget(self.portscan_export_btn)

        self.portscan_table = QTableWidget(0, 4)
        self.portscan_table.setHorizontalHeaderLabels(["Port", "Service", "State", "Banner"])
        self.portscan_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.portscan_table.verticalHeader().setVisible(False)
        self.portscan_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.portscan_table.setStyleSheet(
            f"QTableWidget {{ background:{PANEL_BG}; color:{TEXT}; border-radius:8px; gridline-color:#2a2e3a; }}"
            f"QHeaderView::section {{ background:{PANEL_BG}; color:{MUTED}; border:none; padding:6px; }}"
        )
        root.addWidget(self.portscan_table, stretch=1)
        return tab

    def on_scan_clicked(self):
        self.scan_btn.setEnabled(False)
        self.scan_btn.setText("Scanning...")
        self.status_label.setText("Starting scan...")
        self.table.setRowCount(0)

        self.worker = Worker(scan_network)
        # Wire the progress callback to the worker's own signal now that it exists
        self.worker.kwargs["progress_callback"] = self.worker.progress.emit
        self.worker.progress.connect(self.on_progress)
        self.worker.finished.connect(self.on_finished)
        self.worker.error.connect(self.on_error)
        self.worker.start()

    def on_progress(self, message: str):
        self.status_label.setText(message)

    def on_error(self, error_text: str):
        logger.error(f"Network scan failed: {error_text}")
        self.status_label.setText("Scan failed. See logs for details.")
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("Scan Local Network")

    def on_finished(self, summary: ScanSummary):
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("Scan Local Network")

        if summary.error:
            self.status_label.setText(f"⚠ {summary.error}")
            self.summary_label.setText(summary.error)
            return

        self.status_label.setText(f"Scan complete — {summary.subnet}")
        self._render_table(summary)
        self._render_summary(summary)
        self._publish_events(summary)

    def _render_table(self, summary: ScanSummary):
        self.table.setRowCount(len(summary.devices))
        for row, device in enumerate(summary.devices):
            ip_item = QTableWidgetItem(device.ip)
            host_item = QTableWidgetItem(device.hostname or "—")
            status_text = "🆕 NEW" if device.is_new else "Known"
            status_item = QTableWidgetItem(status_text)
            if device.is_new:
                status_item.setForeground(Qt.GlobalColor.yellow)
            self.table.setItem(row, 0, ip_item)
            self.table.setItem(row, 1, host_item)
            self.table.setItem(row, 2, status_item)

    def _render_summary(self, summary: ScanSummary):
        if summary.first_scan:
            text = (
                f"First scan of {summary.subnet}: found {len(summary.devices)} device(s). "
                "This has been saved as the baseline — future scans will flag anything new."
            )
        elif summary.new_devices:
            names = ", ".join(d.ip for d in summary.new_devices[:5])
            more = "" if len(summary.new_devices) <= 5 else f" (+{len(summary.new_devices) - 5} more)"
            text = (
                f"Found {len(summary.devices)} device(s) on {summary.subnet}. "
                f"⚠ {len(summary.new_devices)} NEW since last scan: {names}{more}"
            )
        else:
            text = (
                f"Found {len(summary.devices)} device(s) on {summary.subnet}. "
                "No new devices since the last scan."
            )
        self.summary_label.setText(text)

    def on_export(self):
        path = export_table_to_csv(self, self.table, "network_scan_results.csv")
        if path:
            self.status_label.setText(f"Exported to {path}")

    def _publish_events(self, summary: ScanSummary):
        if summary.new_devices and not summary.first_scan:
            event = SecurityEvent(
                source="aid_box.network_scanner",
                category="aid_box",
                title=f"{len(summary.new_devices)} new device(s) detected on {summary.subnet}",
                severity="high",
                details={
                    "subnet": summary.subnet,
                    "new_devices": [d.ip for d in summary.new_devices],
                    "total_devices": len(summary.devices),
                },
            )
        else:
            event = SecurityEvent(
                source="aid_box.network_scanner",
                category="aid_box",
                title=f"Scanned {summary.subnet}: {len(summary.devices)} device(s) found",
                severity="info",
                details={
                    "subnet": summary.subnet,
                    "total_devices": len(summary.devices),
                    "first_scan": summary.first_scan,
                },
            )
        self.event_bus.publish(event)
        logger.info(event.title)

    # ---------- Port Scanner tab ----------

    def on_portscan_clicked(self):
        target = self.target_input.text().strip()
        if not target:
            self.portscan_status_label.setText("Enter a target IP or hostname first.")
            return

        self.portscan_btn.setEnabled(False)
        self.portscan_btn.setText("Scanning...")
        self.portscan_table.setRowCount(0)
        self.portscan_status_label.setText("Starting port scan...")

        ports = QUICK_SCAN_PORTS if self.scan_mode_combo.currentIndex() == 0 else list(range(1, 1025))
        grab_banners = self.banner_check.isChecked()

        self.portscan_worker = Worker(scan_ports, target, ports, grab_banners)
        self.portscan_worker.kwargs["progress_callback"] = self.portscan_worker.progress.emit
        self.portscan_worker.progress.connect(self.on_portscan_progress)
        self.portscan_worker.finished.connect(self.on_portscan_finished)
        self.portscan_worker.error.connect(self.on_portscan_error)
        self.portscan_worker.start()

    def on_portscan_progress(self, message: str):
        self.portscan_status_label.setText(message)

    def on_portscan_error(self, error_text: str):
        logger.error(f"Port scan failed: {error_text}")
        self.portscan_status_label.setText("Scan failed. See logs for details.")
        self.portscan_btn.setEnabled(True)
        self.portscan_btn.setText("Scan Ports")

    def on_portscan_finished(self, result: PortScanResult):
        self.portscan_btn.setEnabled(True)
        self.portscan_btn.setText("Scan Ports")

        if result.error:
            self.portscan_status_label.setText(f"⚠ {result.error}")
            return

        self.portscan_status_label.setText(
            f"Scanned {result.scanned_count} port(s) on {result.target} ({result.resolved_ip}) — "
            f"{len(result.open_ports)} open."
        )

        self.portscan_table.setRowCount(len(result.open_ports))
        for row, p in enumerate(result.open_ports):
            self.portscan_table.setItem(row, 0, QTableWidgetItem(str(p.port)))
            self.portscan_table.setItem(row, 1, QTableWidgetItem(p.service))
            state_item = QTableWidgetItem(p.state)
            state_item.setForeground(Qt.GlobalColor.green)
            self.portscan_table.setItem(row, 2, state_item)
            self.portscan_table.setItem(row, 3, QTableWidgetItem(p.banner or "—"))

        self.event_bus.publish(SecurityEvent(
            source="aid_box.network_scanner",
            category="aid_box",
            title=f"Port scan of {result.target}: {len(result.open_ports)} open port(s) found",
            severity="medium" if len(result.open_ports) > 5 else "info",
            details={"target": result.target, "open_count": len(result.open_ports)},
        ))
        logger.info(f"Port scan complete: {result.target} — {len(result.open_ports)} open")

    def on_portscan_export(self):
        path = export_table_to_csv(self, self.portscan_table, "port_scan_results.csv")
        if path:
            self.portscan_status_label.setText(f"Exported to {path}")


def get_widget(event_bus):
    return NetworkScannerWidget(event_bus)
