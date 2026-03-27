"""Plugin registry — maps language name to its LanguagePlugin instance.

To add a new language:
1. Create vuljector/plugins/{lang}_plugin.py
2. Import the plugin class here
3. Add it to PLUGIN_REGISTRY
"""

from selector.static_analysis.plugins.python_plugin import PythonPlugin
from selector.static_analysis.plugins.c_plugin import CPlugin
from selector.static_analysis.plugins.js_plugin import JsPlugin
# from selector.static_analysis.plugins.go_plugin import GoPlugin      # future
# from selector.static_analysis.plugins.java_plugin import JavaPlugin  # future

_c_plugin_instance = CPlugin()
_js_plugin_instance = JsPlugin()

PLUGIN_REGISTRY: dict[str, object] = {
    "python": PythonPlugin(),
    "c":      _c_plugin_instance,
    "cpp":    _c_plugin_instance,
    "c++":    _c_plugin_instance,
    "js":     _js_plugin_instance,
    "ts":     _js_plugin_instance,
    "jsx":    _js_plugin_instance,
    "tsx":    _js_plugin_instance,
}


def get_plugin(language: str):
    """Return the plugin for a language, or None if not supported."""
    return PLUGIN_REGISTRY.get(language)
