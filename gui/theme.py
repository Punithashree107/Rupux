"""
Global dark theme stylesheet applied once at app startup.
Keeps every plugin visually consistent without each tool re-styling itself.
"""
from core.config import DARK_BG, PANEL_BG, ACCENT, TEXT, MUTED

STYLESHEET = f"""
QWidget {{
    background-color: {DARK_BG};
    color: {TEXT};
    font-family: 'Segoe UI', 'Inter', sans-serif;
    font-size: 13px;
}}

QListWidget {{
    border: none;
    padding: 4px;
}}

QListWidget::item {{
    padding: 8px;
    border-radius: 6px;
}}

QListWidget::item:selected {{
    background-color: {ACCENT};
    color: #0f1117;
}}

QPushButton {{
    background-color: {ACCENT};
    color: #0f1117;
    border: none;
    border-radius: 6px;
    padding: 8px 14px;
    font-weight: 600;
}}

QPushButton:hover {{
    background-color: #00c98c;
}}

QPushButton:disabled {{
    background-color: {MUTED};
}}

QLineEdit, QTextEdit, QPlainTextEdit {{
    background-color: {PANEL_BG};
    border: 1px solid #2a2e3a;
    border-radius: 6px;
    padding: 6px;
    color: {TEXT};
}}

QSplitter::handle {{
    background-color: #232734;
}}
"""
