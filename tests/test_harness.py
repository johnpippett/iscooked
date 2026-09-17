"""Regression tests for fixture isolation in the shell test helpers."""

import os
from pathlib import Path

from test_iscooked import run_with_mocks, source_and_run


REPO_ROOT = Path(__file__).resolve().parents[1]


def _print_fixture_paths():
    return 'printf "HOME=%s\\nPWD=%s\\n" "$HOME" "$PWD"'


def test_source_and_run_does_not_inherit_home_or_checkout():
    result = source_and_run(_print_fixture_paths())

    assert result.returncode == 0, result.stderr
    lines = dict(line.split("=", 1) for line in result.stdout_plain.splitlines())
    assert lines["HOME"] != os.environ.get("HOME", "")
    assert lines["PWD"] != str(REPO_ROOT)
    assert Path(lines["HOME"]).name == "home"


def test_source_and_run_preserves_explicit_home(tmp_path):
    fixture_home = tmp_path / "explicit-home"

    result = source_and_run(_print_fixture_paths(), env_vars={"HOME": str(fixture_home)})

    assert result.returncode == 0, result.stderr
    lines = dict(line.split("=", 1) for line in result.stdout_plain.splitlines())
    assert lines["HOME"] == str(fixture_home)
    assert lines["PWD"] != str(REPO_ROOT)


def test_run_with_mocks_keeps_full_scan_in_fixture(tmp_path):
    marker = tmp_path / "paths"
    mock_ss = 'printf "%s\\n%s\\n" "$HOME" "$PWD" > "$HARNESS_MARKER"'

    result = run_with_mocks(
        mocks={
            "ss": mock_ss,
            "uname": "echo Linux",
            "ps": "exit 1",
            "find": "exit 0",
            "python3": "exit 1",
            "curl": "exit 1",
        },
        env_vars={"HARNESS_MARKER": str(marker)},
    )

    assert result.returncode == 0, result.stderr
    home, cwd = marker.read_text().splitlines()[-2:]
    assert home != os.environ.get("HOME", "")
    assert cwd != str(REPO_ROOT)
    assert Path(home).name == "home"
