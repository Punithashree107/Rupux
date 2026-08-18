"""
Persistent app settings for Rupux.

A small JSON file under data/ holding user-tunable values: scan
thresholds, default live-capture duration, and a couple of app
behaviors. Tools read these via get_setting() instead of hardcoding
their thresholds, so the Settings panel actually has an effect.

Falls back to sane defaults if the file doesn't exist yet or a key
is missing, so nothing breaks on first run or after an update adds
a new setting.
"""
import json
import os
from core.config import DATA_DIR

SETTINGS_PATH = os.path.join(DATA_DIR, "settings.json")

DEFAULTS = {
    "live_capture_default_seconds": 10,
    "dos_volumetric_pps_threshold": 100,
    "dos_syn_flood_min_packets": 20,
    "network_scan_thread_workers": 60,
    "password_min_length_recommended": 12,
    "auto_open_dashboard_on_launch": True,
}

_cache = None


def _load_from_disk() -> dict:
    if not os.path.exists(SETTINGS_PATH):
        return dict(DEFAULTS)
    try:
        with open(SETTINGS_PATH, "r") as f:
            data = json.load(f)
        merged = dict(DEFAULTS)
        merged.update(data)
        return merged
    except Exception:
        return dict(DEFAULTS)


def _save_to_disk(settings: dict) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(SETTINGS_PATH, "w") as f:
        json.dump(settings, f, indent=2)


def get_all_settings() -> dict:
    global _cache
    if _cache is None:
        _cache = _load_from_disk()
    return dict(_cache)


def get_setting(key: str):
    return get_all_settings().get(key, DEFAULTS.get(key))


def set_setting(key: str, value) -> None:
    global _cache
    settings = get_all_settings()
    settings[key] = value
    _cache = settings
    _save_to_disk(settings)


def reset_to_defaults() -> None:
    global _cache
    _cache = dict(DEFAULTS)
    _save_to_disk(_cache)
