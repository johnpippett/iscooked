"""Embedded parsers must use Python's isolated standard-library environment."""

import shlex

import pytest

from test_iscooked import source_and_run


@pytest.mark.parametrize("operation", [
    "api_model_metadata Ollama <<<'{\"models\": []}'",
    "check_mcp_config",
    "check_agent_gateway",
    "_model_code_snapshot",
    "browser_debugging_evidence",
    "print_json_report",
])
def test_embedded_parsers_use_isolated_python(operation, tmp_path):
    calls = tmp_path / "python-options"
    wrapper = f'''printf '%s %s\\n' "$1" "$2" >> {shlex.quote(str(calls))}
exec /usr/bin/python3 "$@"
'''
    result = source_and_run(operation, mocks={"python3": wrapper, "ps": "exit 0"},
                            env_vars={"OPENCLAW_CONFIG_PATH": str(tmp_path / "absent.json")})
    assert result.returncode == 0, result.stderr
    assert calls.read_text().splitlines() == ["-I -B"]
