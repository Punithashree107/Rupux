"""
Settings panel: lets the user tune scan thresholds/preferences that
tools actually read via core.settings.get_setting(), plus basic data
management (clear logs, clear the network scanner's device baseline).
"""
import os
import subprocess
import platform
import shutil

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QSpinBox,
    QCheckBox, QFrame, QMessageBox
)

from core.config import TEXT, MUTED, PANEL_BG, ACCENT, DANGER, WARN, DATA_DIR, LOG_DIR
from core.settings import get_all_settings, set_setting, reset_to_defaults
from core.logger import get_logger

logger = get_logger("settings_panel")


def _section_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(f"color:{TEXT}; font-size:14px; font-weight:600; margin-top:14px;")
    return lbl


def _hint_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(f"color:{MUTED}; font-size:11px;")
    lbl.setWordWrap(True)
    return lbl


class SettingsPanel(QWidget):
    def __init__(self):
        super().__init__()
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 24, 24, 24)

        title = QLabel("Settings")
        title.setStyleSheet(f"font-size: 20px; font-weight: 700; color:{TEXT};")
        subtitle = QLabel("Tune the thresholds tools use, and manage locally stored data.")
        subtitle.setStyleSheet(f"color:{MUTED}; margin-bottom: 6px;")
        root.addWidget(title)
        root.addWidget(subtitle)

        settings = get_all_settings()

        # ---------------- Thresholds ----------------
        root.addWidget(_section_label("Scan Thresholds"))

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Default live capture duration (seconds):"))
        self.capture_duration_spin = QSpinBox()
        self.capture_duration_spin.setRange(3, 120)
        self.capture_duration_spin.setValue(settings["live_capture_default_seconds"])
        row1.addWidget(self.capture_duration_spin)
        row1.addStretch(1)
        root.addLayout(row1)
        root.addWidget(_hint_label("Used as the starting value for Packet Analyzer and DoS Detector live capture."))

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("DoS volumetric flood threshold (packets/sec):"))
        self.dos_pps_spin = QSpinBox()
        self.dos_pps_spin.setRange(10, 10000)
        self.dos_pps_spin.setValue(settings["dos_volumetric_pps_threshold"])
        row2.addWidget(self.dos_pps_spin)
        row2.addStretch(1)
        root.addLayout(row2)

        row3 = QHBoxLayout()
        row3.addWidget(QLabel("SYN flood minimum packet count:"))
        self.syn_min_spin = QSpinBox()
        self.syn_min_spin.setRange(5, 1000)
        self.syn_min_spin.setValue(settings["dos_syn_flood_min_packets"])
        row3.addWidget(self.syn_min_spin)
        row3.addStretch(1)
        root.addLayout(row3)

        row4 = QHBoxLayout()
        row4.addWidget(QLabel("Network scan concurrency (parallel pings):"))
        self.scan_workers_spin = QSpinBox()
        self.scan_workers_spin.setRange(10, 200)
        self.scan_workers_spin.setValue(settings["network_scan_thread_workers"])
        row4.addWidget(self.scan_workers_spin)
        row4.addStretch(1)
        root.addLayout(row4)

        row5 = QHBoxLayout()
        row5.addWidget(QLabel("Recommended minimum password length:"))
        self.pw_len_spin = QSpinBox()
        self.pw_len_spin.setRange(6, 32)
        self.pw_len_spin.setValue(settings["password_min_length_recommended"])
        row5.addWidget(self.pw_len_spin)
        row5.addStretch(1)
        root.addLayout(row5)

        # ---------------- Preferences ----------------
        root.addWidget(_section_label("Preferences"))
        self.auto_dashboard_check = QCheckBox("Open Live Dashboard on launch")
        self.auto_dashboard_check.setChecked(settings["auto_open_dashboard_on_launch"])
        root.addWidget(self.auto_dashboard_check)

        save_row = QHBoxLayout()
        save_btn = QPushButton("Save Settings")
        save_btn.clicked.connect(self.on_save)
        reset_btn = QPushButton("Reset to Defaults")
        reset_btn.clicked.connect(self.on_reset)
        save_row.addWidget(save_btn)
        save_row.addWidget(reset_btn)
        save_row.addStretch(1)
        root.addLayout(save_row)

        self.status_label = QLabel("")
        self.status_label.setStyleSheet(f"color:{ACCENT};")
        root.addWidget(self.status_label)

        # ---------------- Data management ----------------
        root.addWidget(_section_label("Data Management"))

        data_frame = QFrame()
        data_frame.setStyleSheet(f"background:{PANEL_BG}; border-radius:10px; padding:14px;")
        data_layout = QVBoxLayout(data_frame)

        open_folder_btn = QPushButton("Open Data Folder")
        open_folder_btn.clicked.connect(self.on_open_data_folder)
        data_layout.addWidget(open_folder_btn)

        clear_baseline_btn = QPushButton("Clear Network Scanner Device Baseline")
        clear_baseline_btn.clicked.connect(self.on_clear_baseline)
        data_layout.addWidget(clear_baseline_btn)
        data_layout.addWidget(_hint_label(
            "Forgets all previously-seen devices — the next network scan will treat "
            "every device as new and re-establish the baseline from scratch."
        ))

        clear_logs_btn = QPushButton("Clear Logs")
        clear_logs_btn.clicked.connect(self.on_clear_logs)
        data_layout.addWidget(clear_logs_btn)

        root.addWidget(data_frame)
        root.addStretch(1)

    def on_save(self):
        set_setting("live_capture_default_seconds", self.capture_duration_spin.value())
        set_setting("dos_volumetric_pps_threshold", self.dos_pps_spin.value())
        set_setting("dos_syn_flood_min_packets", self.syn_min_spin.value())
        set_setting("network_scan_thread_workers", self.scan_workers_spin.value())
        set_setting("password_min_length_recommended", self.pw_len_spin.value())
        set_setting("auto_open_dashboard_on_launch", self.auto_dashboard_check.isChecked())
        self.status_label.setText("✓ Settings saved. Some changes apply next time you run a scan.")
        logger.info("Settings saved")

    def on_reset(self):
        reset_to_defaults()
        self.status_label.setText("✓ Reset to defaults. Reopen Settings to see refreshed values.")
        logger.info("Settings reset to defaults")

    def on_open_data_folder(self):
        try:
            system = platform.system().lower()
            if system == "windows":
                os.startfile(DATA_DIR)
            elif system == "darwin":
                subprocess.run(["open", DATA_DIR])
            else:
                subprocess.run(["xdg-open", DATA_DIR])
        except Exception as e:
            self.status_label.setText(f"Could not open folder: {e}")

    def on_clear_baseline(self):
        confirm = QMessageBox.question(
            self, "Clear device baseline?",
            "This will forget all previously-seen network devices. Continue?",
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return
        baseline_path = os.path.join(DATA_DIR, "known_devices.json")
        if os.path.exists(baseline_path):
            os.remove(baseline_path)
        self.status_label.setText("✓ Network scanner baseline cleared.")
        logger.info("Network scanner baseline cleared by user")

    def on_clear_logs(self):
        confirm = QMessageBox.question(
            self, "Clear logs?",
            "This will delete all Rupux log files. Continue?",
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return
        try:
            for fname in os.listdir(LOG_DIR):
                fpath = os.path.join(LOG_DIR, fname)
                if os.path.isfile(fpath):
                    try:
                        os.remove(fpath)
                    except PermissionError:
                        pass  # today's active log file may still be open/locked
            self.status_label.setText("✓ Logs cleared (today's active log file may remain until restart).")
            logger.info("Logs cleared by user")
        except Exception as e:
            self.status_label.setText(f"Could not clear logs: {e}")
