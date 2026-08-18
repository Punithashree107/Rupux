# Rupux Architecture

## Design goals

1. **One app, many tools** — a user should never feel like they're switching
   applications. Sidebar navigation + shared theme + shared event stream.
2. **Add a tool without touching core code** — new tools are folders with a
   `plugin.py`; the loader, sidebar, and dashboard all pick them up automatically.
3. **The GUI never freezes** — anything slow (scans, cracking, packet capture)
   runs off the main thread via `core/task_manager.py`.
4. **The dashboard is dumb, the tools are smart** — Live Dashboard and Attack
   Navigator only know about `SecurityEvent` objects. They don't import or
   know about any specific tool. This keeps the dashboard stable as tools
   are added/changed/removed.

## Data flow

```
 ┌─────────────┐   publish(SecurityEvent)   ┌───────────────┐
 │  Any Plugin │ ─────────────────────────▶ │   event_bus   │
 │ (Aid Box/   │                             │ (QObject +    │
 │  Hacks tool)│                             │  pyqtSignal)  │
 └─────────────┘                             └───────┬───────┘
                                                       │ event_published
                                        ┌──────────────┼───────────────┐
                                        ▼                              ▼
                              ┌──────────────────┐         ┌────────────────────┐
                              │  Live Dashboard   │         │  Attack Navigator  │
                              │ - risk score      │         │ - rule engine      │
                              │ - activity feed   │         │ - recommendations  │
                              └──────────────────┘         └────────────────────┘
```

## Plugin contract

Every tool under `modules/<category>/<tool_name>/plugin.py` must define:

```python
PLUGIN_METADATA = {
    "id": "aid_box.file_identifier",   # unique, "<category>.<tool_name>"
    "name": "File Type Identifier",     # shown in sidebar
    "category": "aid_box",              # aid_box | hacks | real_zone
    "description": "...",
    "icon": "file-search",              # optional
}

def get_widget(event_bus) -> QWidget:
    # builds and returns the tool's full GUI panel
    ...
```

The tool's widget is responsible for:
- Its own UI (forms, buttons, result display)
- Running its own logic (optionally via `core.task_manager.Worker` if slow)
- Publishing `SecurityEvent`s to `event_bus` when something notable happens

## Core modules

| File | Responsibility |
|---|---|
| `core/event_bus.py` | Shared pub/sub bus (`SecurityEvent` dataclass + Qt signal) |
| `core/plugin_loader.py` | Discovers and imports every `plugin.py` under `modules/` |
| `core/task_manager.py` | `QThread`-based `Worker` for non-blocking tool execution |
| `core/logger.py` | Centralized logging to file + console for every module |
| `core/config.py` | Paths, theme colors, category labels |
| `core/base_plugin.py` | Plugin contract docs + shared placeholder widget helper |

## Severity model

`SecurityEvent.severity` is one of `info | low | medium | high | critical`.
The Live Dashboard converts severity into a numeric weight to build the
running risk score (see `SEVERITY_WEIGHT` in `dashboard/live_dashboard.py`).
Attack Navigator uses severity/category/details to match against its rule
set (see `RULES` in `dashboard/attack_navigator.py`).
