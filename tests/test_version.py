"""Version consistency.

The version is declared twice - `redcell.__version__` and `pyproject.toml` -
so they can drift silently at release time. These tests pin them together, and
pin the CLI's reported version to the same value.
"""

from __future__ import annotations

import pathlib
import re

from typer.testing import CliRunner

import redcell
from redcell.cli import app

_REPO = pathlib.Path(__file__).resolve().parents[1]
runner = CliRunner()


def _pyproject_version() -> str:
    """The version declared in pyproject.toml's [project] table."""
    text = (_REPO / "pyproject.toml").read_text(encoding="utf-8")
    project = text.split("[project]", 1)[1]
    match = re.search(r'^version\s*=\s*"([^"]+)"', project, re.MULTILINE)
    assert match, "no version found in pyproject.toml [project]"
    return match.group(1)


def test_package_version_matches_pyproject():
    assert redcell.__version__ == _pyproject_version()


def test_cli_reports_the_package_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert redcell.__version__ in result.stdout


def test_changelog_documents_the_current_version():
    changelog = (_REPO / "docs" / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"## [{redcell.__version__}]" in changelog, (
        f"docs/CHANGELOG.md has no entry for {redcell.__version__}"
    )
