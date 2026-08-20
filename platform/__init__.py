"""Backend platform package for the email verification helper.

The requested package name matches Python's standard-library ``platform``
module.  Re-export its public API so third-party dependencies importing
``platform`` continue to work when the repository root is on ``sys.path``.
"""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sysconfig

_stdlib_platform_path = Path(sysconfig.get_path("stdlib")) / "platform.py"
_stdlib_platform_spec = spec_from_file_location(
    "_stdlib_platform", _stdlib_platform_path
)
if _stdlib_platform_spec is None or _stdlib_platform_spec.loader is None:
    raise RuntimeError("Python standard-library platform module is unavailable")
_stdlib_platform = module_from_spec(_stdlib_platform_spec)
_stdlib_platform_spec.loader.exec_module(_stdlib_platform)

for _name in dir(_stdlib_platform):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_stdlib_platform, _name)

__version__ = "0.1.1"

__all__ = ["__version__"]
