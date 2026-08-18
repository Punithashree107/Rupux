"""
Auto-discovers every tool under modules/<category>/<tool_name>/plugin.py
and returns their metadata + widget factory so the sidebar and main
window can build themselves dynamically. Add a new tool = drop a new
folder in modules/<category>/ with a plugin.py -- no core code changes.
"""
import importlib
import pkgutil
from types import ModuleType
from typing import List, NamedTuple, Callable

from core.config import MODULES_DIR, CATEGORIES
from core.base_plugin import validate_metadata
from core.logger import get_logger

logger = get_logger("plugin_loader")


class LoadedPlugin(NamedTuple):
    metadata: dict
    get_widget: Callable


def _iter_tool_packages(category: str):
    import os
    category_path = os.path.join(MODULES_DIR, category)
    if not os.path.isdir(category_path):
        return
    for _, tool_name, is_pkg in pkgutil.iter_modules([category_path]):
        if is_pkg:
            yield f"modules.{category}.{tool_name}.plugin"


def discover_plugins() -> List[LoadedPlugin]:
    """Scan every category folder and import each tool's plugin.py."""
    plugins: List[LoadedPlugin] = []

    for category in CATEGORIES:
        for module_path in _iter_tool_packages(category):
            try:
                module: ModuleType = importlib.import_module(module_path)
                metadata = getattr(module, "PLUGIN_METADATA")
                get_widget = getattr(module, "get_widget")
                validate_metadata(metadata)
                plugins.append(LoadedPlugin(metadata=metadata, get_widget=get_widget))
                logger.info(f"Loaded plugin: {metadata['id']}")
            except Exception as e:
                logger.error(f"Failed to load plugin at {module_path}: {e}")

    return plugins
