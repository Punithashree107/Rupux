"""
Plugin entry point for File Type Identifier.
Follows the standard Rupux plugin contract:
  PLUGIN_METADATA dict + get_widget(event_bus) -> QWidget
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFileDialog, QFrame, QListWidget, QListWidgetItem
)
from PyQt6.QtCore import Qt

from core.config import TEXT, MUTED, PANEL_BG, ACCENT, DANGER
from core.event_bus import SecurityEvent
from core.logger import get_logger

from .detector import identify_file

logger = get_logger("aid_box.file_identifier")

PLUGIN_METADATA = {
    "id": "aid_box.file_identifier",
    "name": "File Type Identifier",
    "category": "aid_box",
    "description": "Detects a file's real type from its binary signature and flags extension mismatches.",
    "icon": "file-search",
}


class FileIdentifierWidget(QWidget):
    def __init__(self, event_bus):
        super().__init__()
        self.event_bus = event_bus
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 24, 24, 24)

        title = QLabel("File Type Identifier")
        title.setStyleSheet(f"font-size: 20px; font-weight: 700; color:{TEXT};")
        subtitle = QLabel(
            "Select a file to detect its true type from its binary signature — "
            "useful for catching disguised or spoofed files."
        )
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet(f"color:{MUTED}; margin-bottom: 10px;")

        pick_row = QHBoxLayout()
        self.pick_btn = QPushButton("Choose File...")
        self.pick_btn.clicked.connect(self.on_choose_file)
        self.path_label = QLabel("No file selected")
        self.path_label.setStyleSheet(f"color:{MUTED};")
        pick_row.addWidget(self.pick_btn)
        pick_row.addWidget(self.path_label, stretch=1)

        self.result_frame = QFrame()
        self.result_frame.setStyleSheet(f"background:{PANEL_BG}; border-radius:10px; padding:16px;")
        self.result_layout = QVBoxLayout(self.result_frame)
        self.result_placeholder = QLabel("Results will appear here.")
        self.result_placeholder.setStyleSheet(f"color:{MUTED};")
        self.result_layout.addWidget(self.result_placeholder)

        history_label = QLabel("History (this session)")
        history_label.setStyleSheet(f"font-weight:600; color:{TEXT}; margin-top:12px;")
        self.history = QListWidget()
        self.history.setStyleSheet(f"background:{PANEL_BG}; color:{TEXT}; border-radius:8px;")

        root.addWidget(title)
        root.addWidget(subtitle)
        root.addLayout(pick_row)
        root.addWidget(self.result_frame)
        root.addWidget(history_label)
        root.addWidget(self.history, stretch=1)

    def on_choose_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select a file to identify")
        if not path:
            return
        self.path_label.setText(path)
        result = identify_file(path)
        self._render_result(result)
        self._publish_event(result)

    def _clear_layout(self, layout):
        while layout.count():
            item = layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

    def _render_result(self, result):
        self._clear_layout(self.result_layout)

        if result.error:
            lbl = QLabel(f"⚠ Could not read file: {result.error}")
            lbl.setStyleSheet(f"color:{DANGER};")
            self.result_layout.addWidget(lbl)
            return

        name_lbl = QLabel(f"File: {result.filename}")
        name_lbl.setStyleSheet(f"color:{TEXT}; font-weight:600;")
        type_lbl = QLabel(f"Detected type: {result.detected_type}")
        type_lbl.setStyleSheet(f"color:{ACCENT}; font-size:15px; font-weight:700;")
        size_lbl = QLabel(f"Size: {result.file_size:,} bytes")
        size_lbl.setStyleSheet(f"color:{MUTED};")

        self.result_layout.addWidget(name_lbl)
        self.result_layout.addWidget(type_lbl)
        self.result_layout.addWidget(size_lbl)

        if result.extension_mismatch:
            warn = QLabel(
                f"⚠ Extension mismatch: file is named '{result.extension}' but the content "
                f"matches {result.detected_type}. Treat this file with caution."
            )
            warn.setWordWrap(True)
            warn.setStyleSheet(f"color:{DANGER}; font-weight:600; margin-top:6px;")
            self.result_layout.addWidget(warn)

        # history entry
        summary = f"{result.filename} → {result.detected_type}"
        if result.extension_mismatch:
            summary += "  ⚠ MISMATCH"
        item = QListWidgetItem(summary)
        self.history.insertItem(0, item)

    def _publish_event(self, result):
        if result.error:
            return

        severity = "high" if result.extension_mismatch else "info"
        title = f"Identified '{result.filename}' as {result.detected_type}"
        if result.extension_mismatch:
            title = f"Extension mismatch detected on '{result.filename}'"

        event = SecurityEvent(
            source="aid_box.file_identifier",
            category="aid_box",
            title=title,
            severity=severity,
            details={
                "filename": result.filename,
                "detected_type": result.detected_type,
                "extension": result.extension,
                "extension_mismatch": result.extension_mismatch,
                "file_size": result.file_size,
            },
        )
        self.event_bus.publish(event)
        logger.info(title)


def get_widget(event_bus):
    return FileIdentifierWidget(event_bus)
