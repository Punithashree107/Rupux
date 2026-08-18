"""
Sidebar navigation. Structure:

  ● Live Dashboard            (always present, index 0)
  ▾ Aid Box                   (category header)
      - File Type Identifier  (plugin, only enabled ones show as real tools)
      - Network Device Scanner
      - ...
  ▾ Hacks
      - Cryptanalysis
      - ...
  ● Real Zone                 (single placeholder page)

Built dynamically from whatever plugin_loader.discover_plugins() finds,
so adding a new tool folder automatically adds a sidebar entry.
"""
from PyQt6.QtWidgets import QListWidget, QListWidgetItem
from PyQt6.QtCore import Qt
from core.config import CATEGORIES, MUTED


class Sidebar(QListWidget):
    """Emits currentRowChanged (built-in) which MainWindow listens to,
    mapped via self.page_map to the correct QStackedWidget index."""

    def __init__(self, plugins, parent=None):
        super().__init__(parent)
        self.setFixedWidth(230)
        self.page_map = []  # index -> "dashboard" | plugin_id | "real_zone"
        self._build(plugins)

    def _add_header(self, text: str):
        item = QListWidgetItem(text.upper())
        item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsSelectable)
        item.setForeground(Qt.GlobalColor.gray)
        font = item.font()
        font.setBold(True)
        font.setPointSize(9)
        item.setFont(font)
        self.addItem(item)
        self.page_map.append(None)  # headers don't map to a page

    def _add_entry(self, label: str, page_key: str, indent: bool = False):
        item = QListWidgetItem(("   " if indent else "") + label)
        self.addItem(item)
        self.page_map.append(page_key)

    def _build(self, plugins):
        self._add_entry("🏠  Live Dashboard", "dashboard")

        for category in ("aid_box", "hacks"):
            self._add_header(CATEGORIES[category])
            cat_plugins = [p for p in plugins if p.metadata["category"] == category]
            if not cat_plugins:
                self._add_entry("No tools yet", None, indent=True)
            for p in cat_plugins:
                self._add_entry(p.metadata["name"], p.metadata["id"], indent=True)

        self._add_header("")
        self._add_entry("🌐  Real Zone", "real_zone")
        self._add_entry("⚙️  Settings", "settings")

    def page_key_for_row(self, row: int):
        if 0 <= row < len(self.page_map):
            return self.page_map[row]
        return None
