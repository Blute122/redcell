"""Ensure the repository root is importable so tests can `import evaluation`.

pytest adds each test file's own directory to sys.path, but the evaluation
harness lives in a top-level `evaluation/` package next to it. A root conftest
puts the repo root on the path for the whole session.
"""

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
