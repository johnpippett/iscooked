#!/usr/bin/env python3
"""Regression tests for incomplete local inspection paths.

These tests use command mocks. They do not inspect the host or contact services.
"""

import os
import re
import subprocess
import tempfile
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "iscooked"


def strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def source_and_run(
    function_name,
    mocks=None,
    env_vars=None,
    extra_path="/usr/bin:/bin",
    function_mocks=None,
):
    """Source the scanner and run one function with mocked commands."""
    mocks = mocks or {}
    function_mocks = function_mocks or {}
    with tempfile.TemporaryDirectory() as tmpdir:
        for name, content in mocks.items():
            path = Path(tmpdir) / name
            path.write_text(f"#!/bin/sh\n{content}", encoding="utf-8")
            path.chmod(0o755)

        wrapper = Path(tmpdir) / "wrapper.sh"
        wrapper.write_text(
            f'''#!/bin/bash
set -euo pipefail
/usr/bin/sed '/^main "\\$@"$/d' "{SCRIPT_PATH}" > "{tmpdir}/iscooked_funcs.sh"
source "{tmpdir}/iscooked_funcs.sh"
{os.linesep.join(f'function {name}() {{\n{body}\n}}' for name, body in function_mocks.items())}
export PATH="{tmpdir}:{extra_path}"
OS_TYPE="${{ISCOOKED_TEST_OS_TYPE:-linux}}"
{function_name}
''',
            encoding="utf-8",
        )
        wrapper.chmod(0o755)

        test_env = os.environ.copy()
        test_env["PATH"] = f"{tmpdir}:{extra_path}"
        isolated_home = Path(tmpdir) / "home"
        isolated_home.mkdir()
        test_env["HOME"] = str((env_vars or {}).get("HOME", isolated_home))
        if env_vars:
            test_env.update(env_vars)

        result = subprocess.run(
            ["/bin/bash", str(wrapper)],
            capture_output=True,
            text=True,
            env=test_env,
            cwd=tmpdir,
        )
        result.stdout_plain = strip_ansi(result.stdout)
        result.stderr_plain = strip_ansi(result.stderr)
        return result


def test_network_missing_tools_is_skipped():
    result = source_and_run(
        "check_network_exposure",
        env_vars={"ISCOOKED_TEST_PROC_NET": "/nonexistent"},
        function_mocks={
            "command_exists": '''
case "$1" in
  ss|netstat) return 1 ;;
  *) command -v "$1" >/dev/null 2>&1 ;;
esac
'''
        },
    )

    assert result.returncode == 0, result.stderr_plain
    assert "No common AI service ports detected as listening" not in result.stdout_plain
    assert "SKIP" in result.stdout_plain
    assert "ss or netstat" in result.stdout_plain


def test_network_command_failure_is_unknown():
    result = source_and_run(
        "check_network_exposure",
        mocks={"ss": "exit 1", "netstat": "exit 1"},
    )

    assert result.returncode == 0, result.stderr_plain
    assert "No common AI service ports detected as listening" not in result.stdout_plain
    assert "UNKNOWN" in result.stdout_plain
    assert "listener inspection failed" in result.stdout_plain


def test_api_bind_failure_is_reported_before_local_fallback():
    result = source_and_run(
        "check_api_auth",
        mocks={"ss": "exit 1", "netstat": "exit 1", "curl": "echo 000"},
    )

    assert result.returncode == 0, result.stderr_plain
    assert "API bind exposure inspection failed" in result.stdout_plain
    assert "UNKNOWN" in result.stdout_plain


def test_stat_failure_is_not_reported_as_restrictive(tmp_path):
    home = tmp_path / "home"
    (home / ".ollama").mkdir(parents=True)

    result = source_and_run(
        "check_sensitive_files",
        mocks={"stat": "exit 1"},
        env_vars={"HOME": str(home)},
    )

    assert result.returncode == 0, result.stderr_plain
    assert "UNKNOWN" in result.stdout_plain
    assert "owner inspection failed" in result.stdout_plain
    assert "instead of you" not in result.stdout_plain


def test_env_secret_read_failure_is_unknown(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / ".env").write_text("API_KEY=value\n", encoding="utf-8")

    result = source_and_run(
        "check_sensitive_files",
        mocks={"grep": "exit 2"},
        env_vars={"HOME": str(home)},
    )

    assert result.returncode == 0, result.stderr_plain
    assert "Secret scan failed" in result.stdout_plain
    assert "No world-readable .env files with API keys found" not in result.stdout_plain


def test_env_search_failure_is_unknown(tmp_path):
    home = tmp_path / "home"
    home.mkdir()

    result = source_and_run(
        "check_sensitive_files",
        mocks={"find": "exit 1"},
        env_vars={"HOME": str(home)},
    )

    assert result.returncode == 0, result.stderr_plain
    assert "Sensitive file search incomplete" in result.stdout_plain
    assert "No world-readable .env files with API keys found" not in result.stdout_plain


def test_history_grep_failure_is_unknown(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / ".bash_history").write_text("echo test\n", encoding="utf-8")

    result = source_and_run(
        "check_history_logs",
        mocks={"grep": "exit 2"},
        env_vars={"HOME": str(home)},
    )

    assert result.returncode == 0, result.stderr_plain
    assert "UNKNOWN" in result.stdout_plain
    assert "Shell history inspection failed" in result.stdout_plain
    assert "No API keys found in .bash_history" not in result.stdout_plain


def test_process_command_failure_is_unknown():
    result = source_and_run("check_processes", mocks={"ps": "exit 1"})

    assert result.returncode == 0, result.stderr_plain
    assert "AI process inspection failed" in result.stdout_plain
    assert "No AI-related processes running" not in result.stdout_plain


def test_process_arguments_are_not_printed():
    secret = "sk-123456789012345678901234567890"
    mock_ps = f'''
if [ "$1" = "aux" ]; then
    echo 'alice       1234  0.0  0.1  12345  6789 pts/0    S+   10:00   0:00 vllm serve --api-key {secret}'
fi
'''
    result = source_and_run("check_processes", mocks={"ps": mock_ps})

    assert result.returncode == 0, result.stderr_plain
    assert "vllm" in result.stdout_plain
    assert secret not in result.stdout_plain
    assert "--api-key" not in result.stdout_plain


def test_long_process_arguments_do_not_abort_scan():
    mock_ps = '''
if [ "$1" = "aux" ]; then
    printf '%s' 'alice       1234  0.0  0.1  12345  6789 pts/0    S+   10:00   0:00 vllm '
    i=0
    while [ "$i" -lt 70000 ]; do
        printf 'x'
        i=$((i + 1))
    done
    printf '\\n'
fi
'''
    result = source_and_run("check_processes", mocks={"ps": mock_ps})

    assert result.returncode == 0, result.stderr_plain
    assert "vllm" in result.stdout_plain


def test_tls_failed_probe_is_not_safe():
    mock_ss = '''
if [ "$1" = "-tlnp" ]; then
    echo 'LISTEN 0 128 0.0.0.0:11434 users:(("ollama",pid=12345,fd=3))'
fi
'''
    mock_curl = "echo 000\nexit 7"
    result = source_and_run(
        "check_ssl_tls",
        mocks={"ss": mock_ss, "curl": mock_curl},
    )

    assert result.returncode == 0, result.stderr_plain
    assert "UNKNOWN" in result.stdout_plain
    assert "No AI services exposed over plain HTTP" not in result.stdout_plain


def test_tls_probe_disables_curl_config(tmp_path):
    args_log = tmp_path / "curl.args"
    mock_ss = '''
if [ "$1" = "-tlnp" ]; then
    echo 'LISTEN 0 128 0.0.0.0:11434 users:(('"'"'ollama'"'"',pid=12345,fd=3))'
fi
'''
    mock_curl = '''
echo "$*" >> "$ISCOOKED_CURL_ARGS"
echo 000
exit 0
'''
    result = source_and_run(
        "check_ssl_tls",
        mocks={"ss": mock_ss, "curl": mock_curl},
        env_vars={"ISCOOKED_CURL_ARGS": str(args_log)},
    )

    assert result.returncode == 0, result.stderr_plain
    calls = args_log.read_text(encoding="utf-8").splitlines()
    assert calls
    assert all("-q" in call for call in calls)


def test_tls_does_not_probe_non_ip_listener_address(tmp_path):
    called = tmp_path / "curl.called"
    mock_ss = '''
if [ "$1" = "-tlnp" ]; then
    echo 'LISTEN 0 128 attacker.example:11434 users:(('"'"'ollama'"'"',pid=12345,fd=3))'
fi
'''
    mock_curl = f"touch '{called}'\necho 200\nexit 0"
    result = source_and_run(
        "check_ssl_tls",
        mocks={"ss": mock_ss, "curl": mock_curl},
    )

    assert result.returncode == 0, result.stderr_plain
    assert "unsupported listener address" in result.stdout_plain
    assert not called.exists()


def test_world_write_permission_failure_is_unknown(tmp_path):
    home = tmp_path / "home"
    (home / ".ollama" / "models").mkdir(parents=True)
    mock_find = '''
case "$*" in
  *'-perm -o+r'*) exit 0 ;;
  *'-maxdepth 2'*) exit 1 ;;
  *) exit 1 ;;
esac
'''
    result = source_and_run(
        "check_model_permissions",
        mocks={"find": mock_find},
        env_vars={"HOME": str(home)},
    )

    assert result.returncode == 0, result.stderr_plain
    assert "world-write inspection incomplete" in result.stdout_plain
    assert "No world-readable file modes found" in result.stdout_plain


@pytest.mark.parametrize("host,expected", [
    ("127.0.0.1", "accepted"),
    ("192.168.1.40", "accepted"),
    ("::1", "accepted"),
    ("face.cafe", "rejected"),
    ("999.1.1.1", "rejected"),
    ("010.1.1.1", "rejected"),
])
def test_literal_address_fallback_without_python(host, expected):
    result = source_and_run(
        f"if is_numeric_ip_host '{host}'; then echo accepted; else echo rejected; fi",
        function_mocks={"command_exists": '[[ "$1" != python3 ]]'},
    )
    assert result.stdout.strip() == expected


@pytest.mark.parametrize("platform", ["linux", "macos"])
def test_missing_firewall_tools_do_not_prove_inactive_firewall(platform):
    result = source_and_run(
        "check_firewall",
        env_vars={"ISCOOKED_TEST_OS_TYPE": platform},
        function_mocks={"command_exists": "return 1",
                        "ai_service_exposure": "echo port 11434; return 0"},
    )
    assert "UNKNOWN" in result.stdout_plain
    assert "No active firewall detected" not in result.stdout_plain


def test_sensitive_file_limit_is_reported(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    for number in range(21):
        path = home / f"fixture{number}.env"
        path.write_text("SETTING=fixture\n")
        path.chmod(0o600)
    result = source_and_run("check_sensitive_files", env_vars={"HOME": str(home)})
    assert result.returncode == 0, result.stderr
    assert "20-file limit" in result.stdout_plain
    assert "No world-readable .env files with API keys found" not in result.stdout_plain


PROC_TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:2CAA 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1FFC 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1 0000000000000000 100 0 0 10 0
   2: 0100007F:2CAA 0100007F:9C40 01 00000000:00000000 00:00000000 00000000     0        0 3 1 0000000000000000 100 0 0 10 0
"""
PROC_TCP6 = """  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:04D2 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000000000000:1F40 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5 1 0000000000000000 100 0 0 10 0
   2: 0000000000000000FFFF00000A00000A:0BB8 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 6 1 0000000000000000 100 0 0 10 0
"""


def test_proc_net_fallback_without_ss_or_netstat(tmp_path):
    (tmp_path / "tcp").write_text(PROC_TCP)
    (tmp_path / "tcp6").write_text(PROC_TCP6)
    result = source_and_run(
        "proc_net_listen_lines",
        env_vars={"ISCOOKED_TEST_OS_TYPE": "linux", "ISCOOKED_TEST_PROC_NET": str(tmp_path)},
    )
    assert result.returncode == 0, result.stderr_plain
    assert result.stdout_plain.splitlines() == [
        "LISTEN 0 0 0.0.0.0:11434 *:*",
        "LISTEN 0 0 127.0.0.1:8188 *:*",
        "LISTEN 0 0 [::1]:1234 *:*",
        "LISTEN 0 0 [::]:8000 *:*",
        "LISTEN 0 0 [::ffff:10.0.0.10]:3000 *:*",
    ]


def test_network_exposure_uses_proc_net_fallback(tmp_path):
    (tmp_path / "tcp").write_text(PROC_TCP)
    result = source_and_run(
        "check_network_exposure",
        env_vars={"ISCOOKED_TEST_OS_TYPE": "linux", "ISCOOKED_TEST_PROC_NET": str(tmp_path)},
        function_mocks={"command_exists": 'case "$1" in ss|netstat) return 1 ;; *) command -v "$1" >/dev/null 2>&1 ;; esac'},
    )
    assert result.returncode == 0, result.stderr_plain
    assert "port 11434 (commonly Ollama) is listening on ALL interfaces" in result.stdout_plain
    assert "port 8188 (commonly ComfyUI) is bound to localhost only" in result.stdout_plain
    assert "ss or netstat" not in result.stdout_plain
