from __future__ import annotations

"""browser-forensics Cell — test configuration."""

import sys
from pathlib import Path

_cell_dir = Path(__file__).resolve().parent.parent
if str(_cell_dir) not in sys.path:
    sys.path.insert(0, str(_cell_dir))

_project_root = _cell_dir.parent.parent
if (_project_root / "forhacker" / "__init__.py").exists():
    if str(_project_root) not in sys.path:
        sys.path.insert(0, str(_project_root))
