"""Coverage records for the root scanner artifact."""

import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "iscooked"
CHECKS = (
    "network_exposure api_auth model_permissions docker_risks gpu_exposure "
    "telemetry firewall ssl_tls processes sensitive_files history_logs "
    "ollama_config browser_debugging mcp_config agent_gateway model_code_execution"
).split()


def run_fixture(check_bodies, *args):
    """Run root main with every detector replaced by a local fixture."""
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        sourced = directory / "iscooked-functions.sh"
        sourced.write_text(
            "\n".join(
                line
                for line in SCANNER.read_text().splitlines()
                if line != 'main "$@"'
            )
            + "\n",
            encoding="utf-8",
        )
        definitions = []
        for name in CHECKS:
            body = check_bodies.get(name, ":")
            definitions.append(f"check_{name}() {{\n{body}\n}}")
        wrapper = directory / "wrapper.sh"
        wrapper.write_text(
            "\n".join(
                [
                    "#!/usr/bin/env bash",
                    'source "$1"',
                    "shift",
                    *definitions,
                    'main "$@"',
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        wrapper.chmod(0o700)
        home = directory / "home"
        home.mkdir()
        environment = os.environ.copy()
        environment.update({"HOME": str(home), "PATH": "/usr/bin:/bin"})
        result = subprocess.run(
            ["bash", str(wrapper), str(sourced), *args],
            cwd=directory,
            env=environment,
            capture_output=True,
            text=True,
        )
        return result


def test_silent_checks_get_distinct_skip_records_and_coverage():
    result = run_fixture({}, "--json")

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["summary"]["status"] == "inconclusive"
    assert report["summary"]["counts"] == {
        "critical": 0,
        "warning": 0,
        "passed": 0,
        "unknown": 0,
        "skipped": 16,
        "total": 16,
    }
    assert report["coverage"] == {
        "areas_started": 16,
        "areas_with_observations": 0,
        "areas_with_unknown": 0,
        "areas_with_skips": 16,
    }
    assert len(report["findings"]) == 16
    assert all(item["status"] == "skipped" for item in report["findings"])


def test_coverage_counts_distinct_areas_and_keeps_all_statuses():
    bodies = {
        "network_exposure": 'section "01" "Network Exposure"\nresult_safe "Observed"',
        "api_auth": 'section "02" "API Authentication"\nresult_unknown "Unavailable"',
        "model_permissions": 'section "03" "Model Permissions"\nresult_skip "Not applicable"',
        "docker_risks": 'section "04" "Docker"\nresult_cooked "Risk"\nresult_safe "Other observation"',
    }
    result = run_fixture(bodies, "--json")

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["summary"]["status"] == "critical"
    assert report["coverage"] == {
        "areas_started": 16,
        "areas_with_observations": 2,
        "areas_with_unknown": 1,
        "areas_with_skips": 13,
    }
    assert {item["status"] for item in report["findings"]} == {
        "critical",
        "passed",
        "unknown",
        "skipped",
    }


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ('section "01" "Network Exposure"\nresult_skip "Not applicable"', "inconclusive"),
        ('section "01" "Network Exposure"\nresult_unknown "Unavailable"', "inconclusive"),
        ('section "01" "Network Exposure"\nresult_safe "Observed"', "inconclusive"),
        ('section "01" "Network Exposure"\nresult_warming "Review"\nresult_skip "Gap"', "warning"),
        ('section "01" "Network Exposure"\nresult_cooked "Risk"\nresult_skip "Gap"', "critical"),
    ],
)
def test_summary_status_keeps_risk_precedence(body, expected):
    result = run_fixture({"network_exposure": body}, "--json")

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["summary"]["status"] == expected


def test_json_score_keeps_raw_points_when_display_value_is_capped():
    result = run_fixture(
        {
            "network_exposure": (
                'section "01" "Network Exposure"\n'
                "for n in {1..12}; do result_cooked 'Risk'; done"
            )
        },
        "--json",
    )

    assert result.returncode == 0, result.stderr
    score = json.loads(result.stdout)["summary"]["score"]
    assert score["value"] == 100
    assert score["raw_value"] == 120


def test_all_observed_safe_areas_can_report_no_findings():
    result = run_fixture({name: 'result_safe "Observed"' for name in CHECKS}, "--json")

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["summary"]["status"] == "no_findings"
    assert report["coverage"] == {
        "areas_started": 16,
        "areas_with_observations": 16,
        "areas_with_unknown": 0,
        "areas_with_skips": 0,
    }
