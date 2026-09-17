"""Environment values describe this scan, not a running service."""

import pytest

from test_iscooked import source_and_run


@pytest.mark.parametrize("value", ["0", "false", "FALSE", "False", "f", "F"])
def test_false_cloud_flag_does_not_pass(value):
    result = source_and_run("check_telemetry", env_vars={"OLLAMA_NO_CLOUD": value, "DO_NOT_TRACK": ""})
    assert "SAFE" not in result.stdout_plain
    assert "SKIP" in result.stdout_plain


def test_telemetry_does_not_collect_unused_connections():
    result = source_and_run("check_telemetry", mocks={"ss": "echo SOCKET-CANARY >&2; exit 99"},
                            env_vars={"OLLAMA_NO_CLOUD": "", "DO_NOT_TRACK": ""})
    assert "SOCKET-CANARY" not in result.stderr
    assert "SKIP" in result.stdout_plain


@pytest.mark.parametrize("host", ["::1", "[::1]:11434", "http://[::1]:11434", "http://127.0.0.1:11434"])
def test_loopback_environment_is_not_wildcard_exposure(host):
    result = source_and_run("check_ollama_config", mocks={"ollama": "exit 0"},
                            env_vars={"OLLAMA_HOST": host, "OLLAMA_ORIGINS": ""})
    assert "COOKED" not in result.stdout_plain
    assert "loopback" in result.stdout_plain
    assert "scanner environment" in result.stdout_plain


@pytest.mark.parametrize("host", ["http://0.0.0.0:11434", "[::]:11434", "::"])
def test_wildcard_environment_is_recognized_without_claiming_runtime(host):
    result = source_and_run("check_ollama_config", mocks={"ollama": "exit 0"},
                            env_vars={"OLLAMA_HOST": host, "OLLAMA_ORIGINS": ""})
    assert "COOKED" in result.stdout_plain
    assert "scanner environment" in result.stdout_plain
    assert "verify" in result.stdout_plain


def test_environment_values_do_not_disclose_url_credentials():
    result = source_and_run("check_ollama_config", mocks={"ollama": "exit 0"},
                            env_vars={"OLLAMA_HOST": "http://user:SECRET-CANARY@example.invalid:11434",
                                      "OLLAMA_ORIGINS": "https://SECRET-CANARY.example.invalid"})
    assert "SECRET-CANARY" not in result.stdout
    assert "UNKNOWN" in result.stdout_plain
