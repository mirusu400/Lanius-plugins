from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from packaging.version import Version

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def load_plugin(plugin_id: str):
    versions = sorted(
        (path for path in (ROOT / "plugins" / plugin_id).iterdir() if path.is_dir()),
        key=lambda path: Version(path.name),
        reverse=True,
    )
    source = versions[0] / "plugin.py"
    module_name = "test_plugin_" + plugin_id.replace(".", "_").replace("-", "_")
    spec = importlib.util.spec_from_file_location(module_name, source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module
