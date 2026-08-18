"""
Global configuration and paths for Rupux.
"""
import os

APP_NAME = "Rupux"
APP_VERSION = "0.1.0"

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULES_DIR = os.path.join(BASE_DIR, "modules")
DATA_DIR = os.path.join(BASE_DIR, "data")
ASSETS_DIR = os.path.join(BASE_DIR, "assets")
LOG_DIR = os.path.join(BASE_DIR, "data", "logs")

# Plugin categories -> folder name under modules/
CATEGORIES = {
    "aid_box": "Aid Box",
    "hacks": "Hacks",
    "real_zone": "Real Zone",
}

# Theme
DARK_BG = "#0f1117"
PANEL_BG = "#161923"
ACCENT = "#00e5a0"
WARN = "#ffb020"
DANGER = "#ff4d4f"
TEXT = "#e6e6e6"
MUTED = "#8b8f9c"

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)
