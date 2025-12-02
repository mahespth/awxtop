import sys
from pathlib import Path

# Ensure project root and src/ are on sys.path so `import awxtop` works in tests without install
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
for path in (SRC, ROOT):
    path_str = str(path)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)
