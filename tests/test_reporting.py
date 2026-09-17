"""Regression fixtures for scanner reports and command-line control."""

import json
import os
import subprocess
from pathlib import Path

import pytest

from test_iscooked import source_and_run


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "site" / "iscooked.com"
RELEASE_VERSION = (SCRIPT_PATH.parents[1] / "VERSION").read_text().strip()


CHECKS = (
    "network_exposure api_auth model_permissions docker_risks gpu_exposure "
    "telemetry firewall ssl_tls processes sensitive_files history_logs "
    "ollama_config browser_debugging mcp_config agent_gateway model_code_execution"
).split()


def report(args="", results="result_skip 'No supported fixture found'", env_vars=None):
    mocks = {"check_" + name: ":" for name in CHECKS}
    mocks["check_network_exposure"] = 'section "01" "Network Exposure"\n' + results
    # Keep focused report fixtures from exercising the production coverage
    # wrapper. The production helper accepts one check callback argument.
    mocks["run_check"] = '"$@"'
    return source_and_run("main " + args, function_mocks=mocks, env_vars=env_vars)


def test_real_entrypoint_help_does_not_start_scan(tmp_path):
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)}
    result = subprocess.run(
        ["bash", str(SCRIPT_PATH), "--help"],
        cwd=tmp_path,
        env={**os.environ, **env},
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Usage: bash iscooked.com [options]" in result.stdout
    assert "Scanning your setup" not in result.stdout
    assert result.stderr == ""


@pytest.mark.parametrize("option", ["--help", "-h", "--version"])
def test_information_options_do_not_scan(option):
    result = report(option, "result_cooked 'SCAN-CANARY'")
    assert result.returncode == 0
    assert "SCAN-CANARY" not in result.stdout
    if option == "--version":
        assert result.stdout.strip() == f"iscooked {RELEASE_VERSION}"
    else:
        assert "Usage:" in result.stdout


@pytest.mark.parametrize("option", ["--invalid", "--fail-on", "--fail-on safe", "filename", "--json=anything"])
def test_invalid_options_stop_before_scan(option):
    result = report(option, "result_cooked 'SCAN-CANARY'")
    assert result.returncode == 2
    assert "SCAN-CANARY" not in result.stdout
    assert result.stderr


def test_one_critical_result_demands_attention_at_low_score():
    result = report(results="result_cooked 'Fixture risk'")
    assert result.returncode == 0
    assert "Fix critical findings first." in result.stdout
    assert "10% cooked" in result.stdout
    assert "SLIGHTLY WARM" in result.stdout
    assert "locked down" not in result.stdout
    assert "LOOKING FRESH" not in result.stdout


def test_skipped_only_scan_does_not_claim_protection():
    result = report()
    assert "skipped" in result.stdout_plain
    assert "STILL DEFROSTING" in result.stdout
    assert "LOOKING FRESH" not in result.stdout
    assert "locked down" not in result.stdout


def test_unknown_is_separate_from_warnings():
    result = report(results="result_unknown 'Unavailable fixture'")
    assert "0 warnings" in result.stdout_plain
    assert "1 unknown" in result.stdout_plain
    assert "STILL DEFROSTING" in result.stdout


def test_redirected_output_has_no_terminal_escape_sequences():
    result = report("--no-color", "result_safe 'Fixture passed'")
    assert "\x1b" not in result.stdout
    assert "\x1b" not in report().stdout


def test_no_color_environment_suppresses_terminal_escape_sequences():
    result = report("", "result_safe 'Fixture passed'", env_vars={"NO_COLOR": "1"})
    assert result.returncode == 0
    assert "\x1b" not in result.stdout


def test_json_replaces_invalid_utf8_in_finding_messages():
    result = report("--json", r"result_warming $'invalid\xff-byte'")

    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["findings"][0]["message"] == "invalid\ufffd-byte"


def test_json_records_match_counts_and_preserve_messages():
    result = report("--json", r'''result_cooked 'A "quoted" path with \ backslash'
result_warming 'Second finding'
result_safe 'Observed pass'
result_unknown 'Could not read'
result_skip 'Not applicable'
result_warming $'Control\033[31m\tcharacters\nremoved'
''')
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["schema_version"] == 1
    assert data["completed"] is True
    assert data["summary"]["status"] == "critical"
    assert data["summary"]["counts"] == {
        "critical": 1, "warning": 2, "passed": 1, "unknown": 1, "skipped": 1, "total": 6,
    }
    assert data["summary"]["score"]["value"] == 22
    assert data["summary"]["score"]["includes_unknown"] is True
    assert len(data["findings"]) == 6
    assert data["findings"][0]["message"] == 'A "quoted" path with \\ backslash'
    assert data["findings"][0]["check"] == {"id": "01", "title": "Network Exposure"}
    assert data["findings"][0]["points"] == 10
    assert "\x1b" not in data["findings"][-1]["message"]
    assert "\n" not in data["findings"][-1]["message"]


@pytest.mark.parametrize("policy,results,expected", [
    ("critical", "result_cooked 'risk'", 1),
    ("critical", "result_warming 'warning'", 0),
    ("warning", "result_warming 'warning'", 1),
    ("warning", "result_unknown 'unknown'", 0),
    ("unknown", "result_unknown 'unknown'", 1),
    ("unknown", "result_skip 'skip'", 0),
    ("unknown", "result_safe 'pass'", 0),
])
def test_explicit_exit_policy(policy, results, expected):
    result = report("--json --fail-on " + policy, results)
    assert result.returncode == expected, result.stderr
    assert json.loads(result.stdout)["completed"] is True


def test_score_caps_without_discarding_findings():
    result = report("--json", "for n in {1..12}; do result_cooked 'risk'; done")
    data = json.loads(result.stdout)
    assert data["summary"]["score"]["value"] == 100
    assert data["summary"]["counts"]["critical"] == 12
    assert len(data["findings"]) == 12


def test_json_dependency_failure_does_not_start_scan():
    mocks = {"check_" + name: "result_cooked 'SCAN-CANARY'" for name in CHECKS}
    mocks["command_exists"] = '[[ "$1" != python3 ]]'
    result = source_and_run("main --json", function_mocks=mocks)
    assert result.returncode == 2
    assert "SCAN-CANARY" not in result.stdout
    assert "python3" in result.stderr


@pytest.mark.parametrize("setup,message", [
    ("OS_TYPE=unsupported", "Linux and macOS"),
    ("unset HOME", "HOME"),
    ("command_exists() { [[ $1 != grep ]]; }", "grep"),
])
def test_unsupported_requirements_stop_before_scan(setup, message):
    mocks = {"check_" + name: "result_cooked 'SCAN-CANARY'" for name in CHECKS}
    result = source_and_run(setup + "; main", function_mocks=mocks)
    assert result.returncode == 2
    assert "SCAN-CANARY" not in result.stdout
    assert message in result.stderr


def test_empty_scan_has_valid_json_with_no_protection_claim():
    result = report("--json", ":")
    data = json.loads(result.stdout)
    assert data["findings"] == []
    assert data["summary"]["status"] == "inconclusive"
    assert data["summary"]["counts"]["total"] == 0
