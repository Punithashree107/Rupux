"""
Every tool under modules/aid_box/* and modules/hacks/* must expose a
plugin.py that defines:

    PLUGIN_METADATA = {
        "id": "aid_box.file_identifier",
        "name": "File Type Identifier",
        "category": "aid_box",           # aid_box | hacks | real_zone
        "description": "Detects a file's real type from its binary signature.",
        "icon": "file-search",            # optional, maps to assets/icons
    }

    def get_widget(event_bus) -> QWidget:
        ...

This file documents the contract and provides a tiny placeholder widget
helper that "coming soon" tools can reuse.
"""
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel
from PyQt6.QtCore import Qt

REQUIRED_METADATA_KEYS = {"id", "name", "category", "description"}


def validate_metadata(metadata: dict) -> None:
    missing = REQUIRED_METADATA_KEYS - metadata.keys()
    if missing:
        raise ValueError(f"Plugin metadata missing keys: {missing}")


def placeholder_widget(tool_name: str, note: str = "This tool is coming soon.") -> QWidget:
    w = QWidget()
    layout = QVBoxLayout(w)
    layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
    title = QLabel(f"🛠  {tool_name}")
    title.setStyleSheet("font-size: 20px; font-weight: 600; color: #e6e6e6;")
    title.setAlignment(Qt.AlignmentFlag.AlignCenter)
    sub = QLabel(note)
    sub.setStyleSheet("font-size: 13px; color: #8b8f9c;")
    sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
    layout.addWidget(title)
    layout.addWidget(sub)
    return w
