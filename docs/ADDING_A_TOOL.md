# Adding a New Tool to Rupux

Every tool in **Aid Box** or **Hacks** already exists as a stub. To build one
out, or add a brand new tool, follow this pattern.

## 1. Folder structure

```
modules/<category>/<tool_name>/
├── __init__.py
├── plugin.py       # required — the plugin contract
└── logic.py         # your actual tool logic (any name you like)
```

`<category>` is `aid_box` or `hacks`.

## 2. `plugin.py` contract

```python
from core.base_plugin import placeholder_widget  # only needed for stubs

PLUGIN_METADATA = {
    "id": "aid_box.my_tool",          # "<category>.<folder_name>"
    "name": "My Tool",                 # shown in sidebar + dashboard events
    "category": "aid_box",
    "description": "One line describing what it does.",
    "icon": "wrench",                  # optional, for future icon support
}

def get_widget(event_bus):
    return MyToolWidget(event_bus)
```

## 3. Build the widget

Your widget is a normal `QWidget` — build whatever UI the tool needs
(inputs, buttons, result panels). Two things make it a good Rupux citizen:

**a) Run slow work off the main thread**

```python
from core.task_manager import Worker

self.worker = Worker(my_slow_function, arg1, arg2)
self.worker.finished.connect(self.on_result)
self.worker.error.connect(self.on_error)
self.worker.start()
```

**b) Publish findings to the event bus**

```python
from core.event_bus import SecurityEvent

event = SecurityEvent(
    source="aid_box.my_tool",
    category="aid_box",
    title="Found 3 open ports on 192.168.1.10",
    severity="medium",              # info | low | medium | high | critical
    details={"host": "192.168.1.10", "ports": [22, 80, 443]},
)
event_bus.publish(event)
```

This single call is what makes your tool show up live in the Live Dashboard
feed and lets Attack Navigator react to it.

## 4. That's it

No sidebar code, no dashboard code, no main window code to touch. Restart
the app — `plugin_loader.py` finds your folder automatically because it has
a `plugin.py` with valid `PLUGIN_METADATA` and `get_widget`.

## 5. (Optional) Extend Attack Navigator

If your tool's findings should trigger a specific recommendation, add a rule
in `dashboard/attack_navigator.py`'s `RULES` list — a `(condition_fn, text)`
pair where `condition_fn(event)` returns `True`/`False`.
