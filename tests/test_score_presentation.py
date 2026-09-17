"""Regression fixtures for the playful terminal score presentation."""

import re

import pytest

from test_iscooked import source_and_run
from test_reporting import report


def report_text(results):
    """Run a report with all scanner checks stubbed out."""
    result = report(results=results)
    assert result.returncode == 0, result.stderr
    return result.stdout_plain


def summary_with_score(score, *, cooked=0, warming=0, passed=1, unknown=0, skipped=0):
    """Render print_summary from explicit presentation state."""
    total = cooked + warming + passed + unknown + skipped
    command = (
        f"SCORE={score}; COOKED_COUNT={cooked}; WARMING_COUNT={warming}; "
        f"SAFE_COUNT={passed}; UNKNOWN_COUNT={unknown}; SKIPPED_COUNT={skipped}; "
        f"TOTAL_CHECKS={total}; print_summary"
    )
    result = source_and_run(command)
    assert result.returncode == 0, result.stderr
    return result.stdout_plain


def test_summary_prominently_shows_percentage_and_forty_character_bar():
    output = report_text("result_warming 'Fixture warning'")

    assert "YOUR COOKED SCORE" in output
    score_line = next(line for line in output.splitlines() if re.search(r"%\s+cooked", line, re.I))
    assert re.search(r"\b\d{1,3}%\s+cooked\b", score_line, re.I)
    assert re.search(r"\[[^\]\r\n]{40}\]", score_line)


@pytest.mark.parametrize(
    ("score", "verdict"),
    [
        (14, "LOOKING FRESH"),
        (15, "SLIGHTLY WARM"),
        (39, "SLIGHTLY WARM"),
        (40, "MEDIUM RARE"),
        (69, "MEDIUM RARE"),
        (70, "FULLY COOKED"),
    ],
)
def test_score_verdict_boundaries(score, verdict):
    output = summary_with_score(score)

    assert verdict in output


def test_score_display_caps_at_one_hundred_without_changing_raw_score():
    result = source_and_run(
        'SCORE=123; COOKED_COUNT=1; TOTAL_CHECKS=1; print_summary; printf "RAW_SCORE=%s\\n" "$SCORE"'
    )
    assert result.returncode == 0, result.stderr
    output = result.stdout_plain

    assert re.search(r"\b100%\s+cooked\b", output, re.I)
    assert "123% cooked" not in output.lower()
    assert "RAW_SCORE=123" in output


@pytest.mark.parametrize("finding", ["result_cooked", "result_warming"])
def test_low_score_with_known_risk_is_slightly_warm(finding):
    output = report_text(f"{finding} 'Fixture risk'")

    assert "SLIGHTLY WARM" in output
    assert "LOOKING FRESH" not in output


def test_low_score_with_known_pass_is_looking_fresh():
    output = report_text("result_safe 'Fixture passed'")

    assert "LOOKING FRESH" in output
    assert "STILL DEFROSTING" not in output


@pytest.mark.parametrize(
    "results",
    [
        "result_unknown 'Fixture unavailable'",
        "result_skip 'Fixture not applicable'",
        "result_unknown 'Fixture unavailable'\nresult_skip 'Fixture not applicable'",
    ],
)
def test_without_known_results_summary_is_still_defrosting(results):
    output = report_text(results)

    assert "STILL DEFROSTING" in output
    assert "LOOKING FRESH" not in output


def test_unknown_and_skipped_counts_remain_distinct():
    output = report_text(
        "result_unknown 'Fixture unavailable'\nresult_skip 'Fixture not applicable'"
    )

    assert re.search(r"\b1 unknown\b", output)
    assert re.search(r"\b1 skipped\b", output)


def test_example_fixture_scores_twenty_percent_and_is_slightly_warm():
    results = "\n".join(
        [
            "result_warming 'Fixture warning'",
            *["result_unknown 'Fixture unavailable'"] * 4,
            *["result_safe 'Fixture passed'"] * 4,
            *["result_skip 'Fixture not applicable'"] * 9,
        ]
    )
    output = report_text(results)

    assert re.search(r"\b20%\s+cooked\b", output, re.I)
    assert "SLIGHTLY WARM" in output
    assert "LOOKING FRESH" not in output
    assert re.search(r"\b4 unknown\b", output)
    assert re.search(r"\b9 skipped\b", output)
