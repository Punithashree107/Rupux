"""
Rupux — a single-platform cybersecurity toolkit.
Entry point: wires up the Qt Application, applies the global theme,
and launches MainWindow (Sidebar + Live Dashboard + all discovered tools).
"""
import os
import sys
import platform
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QIcon

from core.config import ASSETS_DIR
from gui.main_window import MainWindow
from gui.theme import STYLESHEET


def _set_windows_taskbar_identity():
    """On Windows, python.exe's own icon is used for the taskbar unless the
    process declares its own App User Model ID -- this makes the taskbar
    icon/grouping use Rupux's icon instead of the generic Python one."""
    if platform.system().lower() == "windows":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("rupux.cybersecurity.toolkit")
        except Exception:
            pass


def main():
    _set_windows_taskbar_identity()
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLESHEET)

    icon_path = os.path.join(ASSETS_DIR, "icons", "rupux_icon.ico")
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
