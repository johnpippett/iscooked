"""Regression and feature tests for coding-agent checks, correlation, and CLI flags."""

import json
import os
from pathlib import Path
import re
import shlex
import subprocess

import pytest
from test_iscooked import source_and_run


ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "iscooked"


def run_iscooked(command, *, mocks=None, env_vars=None, function_mocks=None):
    return source_and_run(
        command,
        mocks=mocks,
        env_vars=env_vars,
        function_mocks=function_mocks,
    )


# ─── Check 01: Coding agent & proxy ports ────────────────────────────────────


@pytest.mark.parametrize(
    ("port", "label"),
    [
        (4000, "LiteLLM proxy"),
        (3001, "AnythingLLM"),
        (18789, "OpenClaw Gateway"),
        (4096, "OpenCode Server"),
    ],
)
def test_check01_detects_coding_agent_and_proxy_ports(port, label):
    ss_line = f"LISTEN 0 128 0.0.0.0:{port} 0.0.0.0:*"
    result = run_iscooked(
        "check_network_exposure",
        mocks={"ss": f"printf '%s\\n' {shlex.quote(ss_line)}", "uname": "echo Linux"},
    )
    assert result.returncode == 0, result.stderr
    assert f"port {port} (commonly {label})" in result.stdout_plain
    assert "COOKED" in result.stdout_plain


# ─── Check 09: Coding agent processes ────────────────────────────────────────


@pytest.mark.parametrize("proc", ["openclaw", "opencode", "litellm", "open-webui", "mcp-server"])
def test_check09_detects_coding_agent_processes(proc):
    mock_ps = f'''
if [ "$1" = "aux" ]; then
    echo "alice 4321 0.0 0.1 1000 1000 ? S 10:00 0:00 /usr/local/bin/{proc} --serve"
fi
'''
    result = run_iscooked("check_processes", mocks={"ps": mock_ps, "uname": "echo Linux"})
    assert result.returncode == 0, result.stderr
    assert proc in result.stdout_plain
    assert "SAFE" in result.stdout_plain


# ─── Check 10: Git-tracked .env & credential store permissions ───────────────


def test_check10_flags_git_tracked_dotenv(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    dotenv = repo / ".env"
    dotenv.write_text("OPENAI_API_KEY=sk-secret-value\n", encoding="utf-8")
    dotenv.chmod(0o600)
    subprocess.run(["git", "add", ".env"], cwd=repo, check=True)

    home = tmp_path / "home"
    home.mkdir()
    result = run_iscooked(
        f"cd {shlex.quote(str(repo))} && check_sensitive_files; echo SCORE=$SCORE",
        env_vars={"HOME": str(home)},
    )
    assert result.returncode == 0, result.stderr
    assert "COOKED" in result.stdout_plain
    assert "tracked by git" in result.stdout_plain
    assert "sk-secret-value" not in result.stdout_plain


@pytest.mark.parametrize(
    ("relpath", "mode", "expected_status", "expected_score"),
    [
        (".claude/.credentials.json", 0o644, "COOKED", 10),
        (".config/opencode/auth.json", 0o640, "WARMING UP", 4),
        (".codex/auth.json", 0o600, "SAFE", 0),
        (".config/gh/hosts.yml", 0o644, "COOKED", 10),
        (".aws/credentials", 0o640, "WARMING UP", 4),
        (".netrc", 0o644, "COOKED", 10),
        (".ssh/id_rsa", 0o640, "WARMING UP", 4),
        (".ssh/id_ed25519", 0o400, "SAFE", 0),
    ],
)
def test_check10_credential_store_permissions_never_print_contents(
    tmp_path, relpath, mode, expected_status, expected_score
):
    home = tmp_path / "home"
    home.mkdir()
    cred = home / relpath
    cred.parent.mkdir(parents=True, exist_ok=True)
    cred.write_text("SECRET_CANARY_TOKEN_VALUE_DO_NOT_LEAK\n", encoding="utf-8")
    cred.chmod(mode)

    result = run_iscooked(
        "check_sensitive_files; echo SCORE=$SCORE",
        env_vars={"HOME": str(home)},
    )
    assert result.returncode == 0, result.stderr
    assert expected_status in result.stdout_plain
    assert "credential store" in result.stdout_plain.lower()
    assert f"SCORE={expected_score}" in result.stdout_plain
    assert "SECRET_CANARY_TOKEN_VALUE_DO_NOT_LEAK" not in result.stdout_plain


# ─── Check 11: Expanded secret patterns in shell history ─────────────────────


@pytest.mark.parametrize(
    "line",
    [
        "export KEY=sk-ant-api03-abcdefghij1234567890",
        "export KEY=sk-proj-abcdefghij1234567890",
        "export KEY=sk-or-v1-abcdefghij1234567890",
        "curl -H 'Authorization: token ghp_abcdefghij1234567890'",
        "export GH=github_pat_11AAAAAA0123456789abcdef",
        "export HF=hf_abcdefghij1234567890",
        "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
        "echo $OPENROUTER_API_KEY",
        "echo $GEMINI_API_KEY",
    ],
)
def test_check11_detects_coding_agent_secret_patterns_without_leaking(tmp_path, line):
    home = tmp_path / "home"
    home.mkdir()
    hist = home / ".bash_history"
    hist.write_text(line + "\n", encoding="utf-8")
    hist.chmod(0o600)

    result = run_iscooked(
        "check_history_logs; echo SCORE=$SCORE",
        env_vars={"HOME": str(home)},
    )
    assert result.returncode == 0, result.stderr
    assert "COOKED" in result.stdout_plain
    assert "SCORE=10" in result.stdout_plain
    assert line not in result.stdout_plain


# ─── Check 15: Claude Code, OpenCode, Codex CLI, Cursor, Invisible Unicode ───


def test_check15_claude_code_bypass_permissions_and_allowlists(tmp_path):
    home = tmp_path / "home"
    work = tmp_path / "work"
    (home / ".claude").mkdir(parents=True)
    (work / ".claude").mkdir(parents=True)
    (home / ".claude" / "settings.json").write_text(
        json.dumps({"permissions": {"defaultMode": "bypassPermissions"}}),
        encoding="utf-8",
    )
    (work / ".claude" / "settings.local.json").write_text(
        json.dumps({"permissions": {"allow": ["Bash(*)", "Bash(curl *)"]}}),
        encoding="utf-8",
    )

    result = run_iscooked(
        f"cd {shlex.quote(str(work))} && check_agent_gateway; echo SCORE=$SCORE",
        env_vars={"HOME": str(home)},
    )
    assert result.returncode == 0, result.stderr
    assert "bypassPermissions" in result.stdout_plain
    assert "COOKED" in result.stdout_plain
    assert "Claude Code" in result.stdout_plain


def test_check15_claude_code_project_hooks_and_writable_hook_script(tmp_path):
    home = tmp_path / "home"
    work = tmp_path / "work"
    home.mkdir()
    (work / ".claude").mkdir(parents=True)
    hook_script = work / "hook.sh"
    hook_script.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    hook_script.chmod(0o777)
    (work / ".claude" / "settings.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {"matcher": "Bash", "hooks": [{"type": "command", "command": "./hook.sh"}]}
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    result = run_iscooked(
        f"cd {shlex.quote(str(work))} && check_agent_gateway; echo SCORE=$SCORE",
        env_vars={"HOME": str(home)},
    )
    assert result.returncode == 0, result.stderr
    assert "COOKED" in result.stdout_plain
    assert "world-writable" in result.stdout_plain


def test_check15_claude_code_project_hooks_private_script_is_warning(tmp_path):
    home = tmp_path / "home"
    work = tmp_path / "work"
    home.mkdir()
    (work / ".claude").mkdir(parents=True)
    hook_script = work / "hook.sh"
    hook_script.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    hook_script.chmod(0o755)
    (work / ".claude" / "settings.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {"matcher": "Bash", "hooks": [{"type": "command", "command": "./hook.sh"}]}
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    result = run_iscooked(
        f"cd {shlex.quote(str(work))} && check_agent_gateway; echo SCORE=$SCORE",
        env_vars={"HOME": str(home)},
    )
    assert result.returncode == 0, result.stderr
    assert "WARMING UP" in result.stdout_plain
    assert "SCORE=4" in result.stdout_plain


def test_check15_opencode_permissive_settings(tmp_path):
    home = tmp_path / "home"
    work = tmp_path / "work"
    (home / ".config" / "opencode").mkdir(parents=True)
    work.mkdir()
    (home / ".config" / "opencode" / "opencode.json").write_text(
        json.dumps({"permission": {"*": "allow"}}),
        encoding="utf-8",
    )
    (work / "opencode.json").write_text(
        json.dumps({"permission": {"bash": "allow", "external_directory": "allow"}}),
        encoding="utf-8",
    )

    result = run_iscooked(
        f"cd {shlex.quote(str(work))} && check_agent_gateway; echo SCORE=$SCORE",
        env_vars={"HOME": str(home)},
    )
    assert result.returncode == 0, result.stderr
    assert "OpenCode" in result.stdout_plain
    assert "COOKED" in result.stdout_plain
    assert "SCORE=20" in result.stdout_plain


def test_check15_codex_cli_approval_and_sandbox(tmp_path):
    home = tmp_path / "home"
    (home / ".codex").mkdir(parents=True)
    (home / ".codex" / "config.toml").write_text(
        'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n',
        encoding="utf-8",
    )
    critical = run_iscooked("check_agent_gateway; echo SCORE=$SCORE", env_vars={"HOME": str(home)})
    assert "COOKED" in critical.stdout_plain and "SCORE=10" in critical.stdout_plain

    (home / ".codex" / "config.toml").write_text(
        'approval_policy = "never"\nsandbox_mode = "workspace-write"\n',
        encoding="utf-8",
    )
    warning = run_iscooked("check_agent_gateway; echo SCORE=$SCORE", env_vars={"HOME": str(home)})
    assert "WARMING UP" in warning.stdout_plain and "SCORE=4" in warning.stdout_plain

    (home / ".codex" / "config.toml").write_text(
        'approval_policy = "on-request"\nsandbox_mode = "workspace-write"\n',
        encoding="utf-8",
    )
    safe = run_iscooked("check_agent_gateway; echo SCORE=$SCORE", env_vars={"HOME": str(home)})
    assert "SAFE" in safe.stdout_plain and "SCORE=0" in safe.stdout_plain


def test_check15_cursor_autorun_and_yolo_mode(tmp_path):
    home = tmp_path / "home"
    settings = home / ".config" / "Cursor" / "User" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text('{\n  // comment\n  "cursor.composer.shouldAutoRun": true,\n}\n', encoding="utf-8")

    result = run_iscooked("check_agent_gateway; echo SCORE=$SCORE", env_vars={"HOME": str(home)})
    assert result.returncode == 0, result.stderr
    assert "Cursor" in result.stdout_plain
    assert "WARMING UP" in result.stdout_plain
    assert "SCORE=4" in result.stdout_plain


@pytest.mark.parametrize(
    ("filename", "payload"),
    [
        ("CLAUDE.md", "Normal\u200bhidden instruction"),
        ("AGENTS.md", "Bidi \u202ehidden"),
        (".cursorrules", "Isolate \u2066text"),
        (".windsurfrules", "Midfile BOM \ufeff here"),
        (".github/copilot-instructions.md", "Tag \U000e0020secret"),
        (".cursor/rules/sec.mdc", "Zero width \u200fchar"),
    ],
)
def test_check15_detects_invisible_unicode_prompt_injection(tmp_path, filename, payload):
    home = tmp_path / "home"
    work = tmp_path / "work"
    home.mkdir()
    target = work / filename
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(payload, encoding="utf-8")

    result = run_iscooked(
        f"cd {shlex.quote(str(work))} && check_agent_gateway; echo SCORE=$SCORE",
        env_vars={"HOME": str(home)},
    )
    assert result.returncode == 0, result.stderr
    assert "COOKED" in result.stdout_plain
    assert "SCORE=10" in result.stdout_plain
    assert filename in result.stdout_plain


def test_check15_clean_instruction_files_and_leading_bom_are_safe(tmp_path):
    home = tmp_path / "home"
    work = tmp_path / "work"
    home.mkdir()
    work.mkdir()
    (work / "AGENTS.md").write_text("\ufeff# Agent Rules\nUse safe commands.\n", encoding="utf-8")
    (work / "CLAUDE.md").write_text("# Claude Rules\nKeep secrets out.\n", encoding="utf-8")

    result = run_iscooked(
        f"cd {shlex.quote(str(work))} && check_agent_gateway; echo SCORE=$SCORE",
        env_vars={"HOME": str(home)},
    )
    assert result.returncode == 0, result.stderr
    assert "SAFE" in result.stdout_plain
    assert "SCORE=0" in result.stdout_plain


# ─── Check 08: HTTPS fallback & Check 01/02/08 Score Correlation ─────────────


def test_check08_https_fallback_marks_safe_when_tls_responds():
    mock_ss = 'echo \'LISTEN 0 128 0.0.0.0:11434 0.0.0.0:* users:(("ollama",pid=1,fd=3))\''
    mock_curl = '''
case "$*" in
  *http://127.0.0.1:11434/*) printf '000'; exit 52 ;;
  *https://127.0.0.1:11434/*) printf '200'; exit 0 ;;
  *) printf '000'; exit 7 ;;
esac
'''
    result = run_iscooked(
        "check_ssl_tls; echo SCORE=$SCORE",
        mocks={"ss": mock_ss, "curl": mock_curl, "uname": "echo Linux"},
    )
    assert result.returncode == 0, result.stderr
    assert "Port 11434 serves HTTPS/TLS on all interfaces" in result.stdout_plain
    assert "SAFE" in result.stdout_plain
    assert "SCORE=0" in result.stdout_plain


def test_full_scan_correlates_exposed_port_across_checks_01_02_08():
    mock_ss = 'echo \'LISTEN 0 128 0.0.0.0:11434 0.0.0.0:* users:(("ollama",pid=1,fd=3))\''
    mock_curl = '''
case "$*" in
  *11434/api/tags*) printf '{"models":[]}\\n200' ;;
  *http://127.0.0.1:11434/*) printf '200' ;;
  *) printf '\\n000'; exit 7 ;;
esac
'''
    result = run_iscooked(
        'main --json --only 01,02,08',
        mocks={"ss": mock_ss, "curl": mock_curl, "uname": "echo Linux"},
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    by_id = {item["check"]["id"]: item for item in report["findings"]}
    assert by_id["01"]["points"] == 10
    assert by_id["02"]["points"] == 4
    assert by_id["08"]["points"] == 0
    assert report["summary"]["score"]["raw_value"] == 14


# ─── Bash 3.2 compatibility static audit ─────────────────────────────────────


def test_scanner_has_no_bash4_only_constructs_and_accepts_bash32():
    source = SCANNER.read_text(encoding="utf-8")
    # Strip embedded Python heredocs before scanning Bash syntax.
    bash_only = re.sub(r"<<'?(?:PY|MCP_PY|GATEWAY_PY)'?\n.*?\n(?:PY|MCP_PY|GATEWAY_PY)\n", "\n", source, flags=re.S)
    assert "declare -A" not in bash_only
    assert "mapfile" not in bash_only
    assert "readarray" not in bash_only
    assert "|&" not in bash_only
    assert not re.search(r"\$\{[^}]*(?:,,|\^\^)\}", bash_only)

    ok = run_iscooked('check_bash_version 3 2')
    assert ok.returncode == 0, ok.stderr
    too_old = run_iscooked('check_bash_version 3 1')
    assert too_old.returncode == 2
    assert "Bash 3.2" in too_old.stderr
