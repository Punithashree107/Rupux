"""
Main application shell: Sidebar (left) + QStackedWidget (right).

Flow:
  1. plugin_loader discovers every tool under modules/aid_box and modules/hacks
  2. Sidebar is built from that list
  3. Each plugin's get_widget(event_bus) builds its page, added to the stack
  4. Live Dashboard + Attack Navigator are built once and always sit at index 0
  5. Real Zone is a single static placeholder page
  6. Clicking a sidebar row switches the QStackedWidget to the matching page
"""
import os
from PyQt6.QtWidgets import QMainWindow, QWidget, QHBoxLayout, QStackedWidget
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon

from core.config import APP_NAME, APP_VERSION, ASSETS_DIR
from core.event_bus import event_bus
from core.plugin_loader import discover_plugins
from core.base_plugin import placeholder_widget
from core.logger import get_logger

from dashboard.live_dashboard import LiveDashboard
from dashboard.attack_navigator import AttackNavigator

from gui.sidebar import Sidebar
from gui.settings_panel import SettingsPanel
from real_zone.panel import RealZonePanel

logger = get_logger("main_window")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION} — Cybersecurity Toolkit")
        self.resize(1200, 760)

        icon_path = os.path.join(ASSETS_DIR, "icons", "rupux_icon.ico")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        # 1. Discover every tool plugin
        self.plugins = discover_plugins()
        logger.info(f"Discovered {len(self.plugins)} plugin(s)")

        # 2. Build sidebar from discovered plugins
        self.sidebar = Sidebar(self.plugins)
        self.sidebar.currentRowChanged.connect(self.on_nav_changed)

        # 3. Build the stacked pages
        self.stack = QStackedWidget()
        self.page_index = {}  # page_key -> stack index

        self._add_dashboard_page()
        self._add_plugin_pages()
        self._add_real_zone_page()
        self._add_settings_page()

        # 4. Assemble layout
        central = QWidget()
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.sidebar)
        layout.addWidget(self.stack, stretch=1)
        self.setCentralWidget(central)

        self.sidebar.setCurrentRow(0)

    def _add_dashboard_page(self):
        self.attack_navigator = AttackNavigator()
        self.dashboard = LiveDashboard(attack_navigator=self.attack_navigator)
        idx = self.stack.addWidget(self.dashboard)
        self.page_index["dashboard"] = idx

    def _add_plugin_pages(self):
        for plugin in self.plugins:
            try:
                widget = plugin.get_widget(event_bus)
            except Exception as e:
                logger.error(f"Failed to build widget for {plugin.metadata['id']}: {e}")
                widget = placeholder_widget(plugin.metadata["name"], "Failed to load tool.")
            idx = self.stack.addWidget(widget)
            self.page_index[plugin.metadata["id"]] = idx

    def _add_real_zone_page(self):
        widget = RealZonePanel(event_bus)
        idx = self.stack.addWidget(widget)
        self.page_index["real_zone"] = idx

    def _add_settings_page(self):
        widget = SettingsPanel()
        idx = self.stack.addWidget(widget)
        self.page_index["settings"] = idx

    def on_nav_changed(self, row: int):
        page_key = self.sidebar.page_key_for_row(row)
        if page_key is None:
            return  # header or empty row, ignore
        idx = self.page_index.get(page_key)
        if idx is not None:
            self.stack.setCurrentIndex(idx)
