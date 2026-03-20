from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
VENDOR = ROOT / ".vendor"

paths = [SRC]
if not Path(sys.executable).resolve().is_relative_to(ROOT):
    paths.insert(0, VENDOR)

for path in paths:
    path_str = str(path)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)

from model_safety_mcp.__main__ import main


if __name__ == "__main__":
    main()
