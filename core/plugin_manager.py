"""
Plugin Manager - Loads and manages plugins
"""

import importlib
import logging
from pathlib import Path
from typing import Any, Optional, Dict

logger = logging.getLogger(__name__)

class PluginManager:
    """Loads and manages scanning plugins"""
    
    def __init__(self):
        self.plugins = {}

    async def load_plugins(self) -> None:
        """Dynamically load all plugins in the plugins directory"""
        plugins_path = Path('plugins')
        for plugin_file in plugins_path.glob("*.py"):
            if plugin_file.stem.startswith("_"):
                continue  # Skip private modules
            
            try:
                module_name = f"plugins.{plugin_file.stem}"
                module = importlib.import_module(module_name)
                plugin_class_name = getattr(module, 'PLUGIN_CLASS_NAME', '')
                if plugin_class_name:
                    plugin_class = getattr(module, plugin_class_name)
                    self.plugins[plugin_file.stem] = plugin_class()
                    logger.info(f"Loaded plugin: {plugin_file.stem}")
                else:
                    logger.warning(f"Plugin class name not defined in {plugin_file.stem}")
            except Exception as e:
                logger.error(f"Failed to load plugin {plugin_file.stem}: {e}")
    
    def get_plugin(self, name: str) -> Optional[Any]:
        """Get a loaded plugin by name"""
        return self.plugins.get(name)
