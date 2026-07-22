"""Public API docstring coverage.

Every public class and function in the shipped package (and the evaluation
harness) carries at least a one-line docstring. This test keeps that true as
the codebase grows rather than relying on a one-off cleanup.

Private names (a single leading underscore) and dunder methods are exempt, the
latter by the usual convention that magic methods document themselves.
"""

from __future__ import annotations

import ast
import pathlib

_ROOTS = ("redcell", "evaluation")
_REPO = pathlib.Path(__file__).resolve().parents[1]


def _is_public(name: str) -> bool:
    if name.startswith("__") and name.endswith("__"):
        return False  # dunder: exempt
    return not name.startswith("_")


def _undocumented() -> list[str]:
    missing: list[str] = []
    for root in _ROOTS:
        for path in sorted((_REPO / root).rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                ):
                    continue
                if not _is_public(node.name):
                    continue
                if not ast.get_docstring(node):
                    rel = path.relative_to(_REPO)
                    missing.append(f"{rel}:{node.lineno} {node.name}")
    return missing


def test_every_public_class_and_function_has_a_docstring():
    missing = _undocumented()
    assert not missing, "missing docstrings:\n  " + "\n  ".join(missing)


def test_every_module_has_a_docstring():
    missing = []
    for root in _ROOTS:
        for path in sorted((_REPO / root).rglob("*.py")):
            if not ast.get_docstring(ast.parse(path.read_text(encoding="utf-8"))):
                missing.append(str(path.relative_to(_REPO)))
    assert not missing, "modules missing docstrings: " + ", ".join(missing)
