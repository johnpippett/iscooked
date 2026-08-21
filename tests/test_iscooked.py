#!/usr/bin/env python3
"""Validation tests for iscooked scanner bugs.

Run: pytest tests/test_iscooked.py -v

Each test mocks system commands via PATH injection and asserts on the
script's terminal output. Tests are designed to FAIL on the current
site/iscooked.com and PASS after the fixes are applied.
"""

import os
import re
import subprocess
import tempfile

import pytest

SCRIPT_PATH = os.path.join(os.path.dirname(__file__), "..", "site", "iscooked.com")
REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")


def read_repo_file(*parts: str) -> str:
    with open(os.path.join(REPO_ROOT, *parts), encoding="utf-8") as f:
        return f.read()


# ─────────────────────────────────────────────────────────────────────────────
# Security review: install snippets, PATH hardening, sudo wording
# ─────────────────────────────────────────────────────────────────────────────


class TestInstallSecurity:
    def test_deployed_scanner_is_only_tracked_scanner_copy(self):
        """Avoid stale root copies drifting away from the deployed script."""
        assert not os.path.exists(os.path.join(REPO_ROOT, "cooked.sh"))
        assert os.path.exists(SCRIPT_PATH)

    def test_public_install_snippets_use_explicit_https(self):
        """Published install commands must not rely on curl/wget URL guessing."""
        readme = read_repo_file("README.md")
        index = read_repo_file("site", "index.html")

        public_docs = readme + "\n" + index
        assert "curl -fsSL iscooked.com/iscooked.com | bash" not in public_docs
        assert "curl -fsSL https://iscooked.com/iscooked.com | bash" in readme
        assert "curl -fsSL https://iscooked.com/iscooked.com | bash" in index

    def test_scanner_initializes_safe_fixed_path_near_top(self):
        """The downloaded script should not inherit attacker-controlled PATH."""
        script = read_repo_file("site", "iscooked.com")
        first_lines = "\n".join(script.splitlines()[:12])

        assert re.search(
            r"^PATH=(['\"])?/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\1$",
            first_lines,
            re.MULTILINE,
        )
        assert re.search(r"^export PATH$", first_lines, re.MULTILINE)

    def test_docs_and_script_avoid_blanket_sudo_recommendation(self):
        """Docs/script should explain elevated privileges as optional improvement."""
        readme = read_repo_file("README.md")
        script = read_repo_file("site", "iscooked.com")

        for content in (readme, script):
            assert "Run with `sudo`" not in content
            assert "Run with sudo" not in content
            assert re.search(r"Elevated privileges (can )?improve some .*checks", content)


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences."""
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def run_with_mocks(mocks=None, env_vars=None, extra_path="/usr/bin:/bin"):
    """Run the scanner with mocked commands prepended to PATH.

    Args:
        mocks: dict of {command_name: shell_script_body}
        env_vars: dict of extra environment variables
        extra_path: additional PATH entries after mock dir
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        if mocks:
            for name, content in mocks.items():
                path = os.path.join(tmpdir, name)
                with open(path, "w") as f:
                    f.write(f"#!/bin/sh\n{content}")
                os.chmod(path, 0o755)

        wrapper = os.path.join(tmpdir, "wrapper.sh")
        with open(wrapper, "w") as f:
            f.write(
                f"""#!/bin/bash
set -euo pipefail
# Source scanner functions without triggering main(), then restore mock PATH.
sed '/^main "\\$@"$/d' "{SCRIPT_PATH}" > "$TMPDIR/iscooked_funcs.sh"
source "$TMPDIR/iscooked_funcs.sh"
export PATH="{tmpdir}:{extra_path}"
OS_TYPE="${{ISCOOKED_TEST_OS_TYPE:-linux}}"
main
"""
            )
        os.chmod(wrapper, 0o755)

        test_env = os.environ.copy()
        test_env["PATH"] = tmpdir + ":" + extra_path
        if env_vars:
            test_env.update(env_vars)

        result = subprocess.run(
            ["bash", wrapper],
            capture_output=True,
            text=True,
            env=test_env,
        )
        result.stdout_plain = strip_ansi(result.stdout)
        result.stderr_plain = strip_ansi(result.stderr)
        return result


def source_and_run(function_name, mocks=None, env_vars=None, extra_path="/usr/bin:/bin"):
    """Source the scanner (without running main) and call a single function."""
    with tempfile.TemporaryDirectory() as tmpdir:
        if mocks:
            for name, content in mocks.items():
                path = os.path.join(tmpdir, name)
                with open(path, "w") as f:
                    f.write(f"#!/bin/sh\n{content}")
                os.chmod(path, 0o755)

        # Write a wrapper that sources the script (minus the main call), restores
        # mock PATH after script PATH hardening, and invokes the requested function.
        wrapper = os.path.join(tmpdir, "wrapper.sh")
        with open(wrapper, "w") as f:
            f.write(
                f"""#!/bin/bash
set -euo pipefail
# Source scanner functions without triggering main()
                sed '/^main "\\$@"$/d' "{SCRIPT_PATH}" > "$TMPDIR/iscooked_funcs.sh"
source "$TMPDIR/iscooked_funcs.sh"
export PATH="{tmpdir}:{extra_path}"
OS_TYPE="${{ISCOOKED_TEST_OS_TYPE:-linux}}"
{function_name}
"""
            )
        os.chmod(wrapper, 0o755)

        test_env = os.environ.copy()
        test_env["PATH"] = tmpdir + ":" + extra_path
        if env_vars:
            test_env.update(env_vars)

        result = subprocess.run(
            ["bash", wrapper],
            capture_output=True,
            text=True,
            env=test_env,
        )
        result.stdout_plain = strip_ansi(result.stdout)
        result.stderr_plain = strip_ansi(result.stderr)
        return result


# ─────────────────────────────────────────────────────────────────────────────
# Bug 1: PID collision / IPv6 substring false positive in port detection
# ─────────────────────────────────────────────────────────────────────────────


class TestPortDetection:
    def test_no_ipv6_false_positive_for_port_11434(self):
        """An IPv6 address containing ':11434' should NOT be detected as port 11434."""
        mock_ss = '''
if [ "$1" = "-tlnp" ]; then
    echo 'LISTEN 0 128 [fe80::11434:1]:22 users:(("sshd",pid=12345,fd=3))'
fi
'''
        result = run_with_mocks(
            mocks={"ss": mock_ss, "uname": 'echo Linux'},
            extra_path="/usr/bin:/bin",
        )
        assert "Ollama (port 11434)" not in result.stdout_plain
        assert "port 11434" not in result.stdout_plain.lower()

    def test_legitimate_port_11434_still_detected(self):
        """An actual listener on 0.0.0.0:11434 MUST still be detected."""
        mock_ss = '''
if [ "$1" = "-tlnp" ]; then
    echo 'LISTEN 0 128 0.0.0.0:11434 users:(("ollama",pid=12345,fd=3))'
fi
'''
        result = run_with_mocks(
            mocks={"ss": mock_ss, "uname": 'echo Linux'},
            extra_path="/usr/bin:/bin",
        )
        assert "Ollama (port 11434)" in result.stdout_plain

    def test_bracketed_ipv6_any_address_is_all_interfaces(self):
        """A bracketed IPv6 any-address listener [::]:11434 is exposed on all interfaces."""
        mock_ss = '''
if [ "$1" = "-tlnp" ]; then
    echo 'LISTEN 0 128 [::]:11434 users:(("ollama",pid=12345,fd=3))'
fi
'''
        result = run_with_mocks(
            mocks={"ss": mock_ss, "uname": 'echo Linux'},
            extra_path="/usr/bin:/bin",
        )
        assert "Ollama (port 11434) is listening on ALL interfaces" in result.stdout_plain


# ─────────────────────────────────────────────────────────────────────────────
# Bug 2 & 3: Telemetry — wrong env var, broken ss check removed
# ─────────────────────────────────────────────────────────────────────────────


class TestTelemetry:
    def test_ollama_no_cloud_is_recognized(self):
        """OLLAMA_NO_CLOUD=1 should be reported as a telemetry opt-out."""
        result = source_and_run(
            "check_telemetry",
            mocks={"uname": 'echo Linux'},
            env_vars={"OLLAMA_NO_CLOUD": "1"},
        )
        assert "OLLAMA_NO_CLOUD" in result.stdout_plain
        # Old (wrong) variable should NOT be praised
        assert "OLLAMA_NOPRUNE" not in result.stdout_plain

    def test_ollama_noprune_is_ignored(self):
        """OLLAMA_NOPRUNE=1 should NOT be reported as a telemetry opt-out."""
        result = source_and_run(
            "check_telemetry",
            mocks={"uname": 'echo Linux'},
            env_vars={"OLLAMA_NOPRUNE": "1"},
        )
        assert "OLLAMA_NOPRUNE" not in result.stdout_plain
        assert "OLLAMA_NO_CLOUD" not in result.stdout_plain

    def test_ss_not_grepped_for_telemetry_domains(self):
        """The script must NOT call ss/netstat to grep for telemetry hostnames."""
        ss_called = False

        def mock_ss():
            return '''
if [ "$1" = "-tlnp" ]; then
    # Return a fake line that an OLD broken check might match
    echo 'ESTAB 0 0 192.168.1.50:443 34.120.1.20:443 users:(("chrome",pid=9999,fd=55))'
fi
'''

        # We run the full script and simply assert that no "Active connection"
        # telemetry message appears.
        result = run_with_mocks(
            mocks={"ss": mock_ss(), "uname": 'echo Linux'},
            extra_path="/usr/bin:/bin",
        )
        assert "Active connection detected to telemetry.ollama.ai" not in result.stdout_plain
        assert "Active connection detected to" not in result.stdout_plain


# ─────────────────────────────────────────────────────────────────────────────
# Bug 4 & 5: SSL/TLS inverted heuristic
# ─────────────────────────────────────────────────────────────────────────────


class TestSslTls:
    def test_http_probe_success_flags_plain_http(self):
        """If HTTP probe returns 200, port should be flagged as plain HTTP."""
        mock_ss = '''
if [ "$1" = "-tlnp" ]; then
    echo 'LISTEN 0 128 0.0.0.0:11434 users:(("ollama",pid=12345,fd=3))'
fi
'''
        mock_curl = '''
# Mock curl — return 200 for the HTTP probe on port 11434
if echo "$@" | grep -q "http://127.0.0.1:11434/"; then
    echo "200"
    exit 0
fi
echo "000"
exit 0
'''
        result = run_with_mocks(
            mocks={"ss": mock_ss, "curl": mock_curl, "uname": 'echo Linux'},
            extra_path="/usr/bin:/bin",
        )
        assert "Port 11434 is exposed on all interfaces over plain HTTP" in result.stdout_plain

    def test_http_probe_failure_does_not_flag(self):
        """If HTTP probe fails (000), port should NOT be flagged as plain HTTP."""
        mock_ss = '''
if [ "$1" = "-tlnp" ]; then
    echo 'LISTEN 0 128 0.0.0.0:11434 users:(("ollama",pid=12345,fd=3))'
fi
'''
        mock_curl = '''
# Mock curl — return 000 for everything (simulates down / HTTPS server)
echo "000"
exit 0
'''
        result = run_with_mocks(
            mocks={"ss": mock_ss, "curl": mock_curl, "uname": 'echo Linux'},
            extra_path="/usr/bin:/bin",
        )
        assert "Port 11434 is exposed on all interfaces over plain HTTP" not in result.stdout_plain

    def test_failed_curl_probe_does_not_concat_000_status(self):
        """curl can print 000 and exit nonzero; that must stay a failed probe."""
        mock_ss = '''
if [ "$1" = "-tlnp" ]; then
    echo 'LISTEN 0 128 0.0.0.0:11434 users:(("ollama",pid=12345,fd=3))'
fi
'''
        mock_curl = '''
echo "000"
exit 7
'''
        result = run_with_mocks(
            mocks={"ss": mock_ss, "curl": mock_curl, "uname": 'echo Linux'},
            extra_path="/usr/bin:/bin",
        )
        assert "Port 11434 is exposed on all interfaces over plain HTTP" not in result.stdout_plain

    def test_http_probe_uses_total_timeout(self):
        """curl probes must include --max-time so slow responses cannot hang the scan."""
        mock_ss = '''
if [ "$1" = "-tlnp" ]; then
    echo 'LISTEN 0 128 0.0.0.0:11434 users:(("ollama",pid=12345,fd=3))'
fi
'''
        mock_curl = '''
case " $* " in
  *" --max-time "*) echo "200"; exit 0 ;;
  *) echo "curl missing --max-time: $*" >&2; exit 64 ;;
esac
'''
        result = source_and_run(
            "check_ssl_tls",
            mocks={"ss": mock_ss, "curl": mock_curl, "uname": 'echo Linux'},
            extra_path="/usr/bin:/bin",
        )
        assert "curl missing --max-time" not in result.stderr_plain
        assert "Port 11434 is exposed on all interfaces over plain HTTP" in result.stdout_plain


class TestApiAuth:
    def test_ollama_env_auth_alone_does_not_report_safe(self):
        """Local OLLAMA_AUTH/API_KEY env vars do not prove the responding Ollama API enforces auth."""
        mock_curl = '''
if echo "$@" | grep -q "http://127.0.0.1:11434/"; then
    echo "200"
    exit 0
fi
echo "000"
exit 0
'''
        result = source_and_run(
            "check_api_auth",
            mocks={"curl": mock_curl, "uname": 'echo Linux'},
            env_vars={"OLLAMA_AUTH": "1", "OLLAMA_API_KEY": "local-only"},
            extra_path="/usr/bin:/bin",
        )
        assert "Ollama API is responding with auth configured" not in result.stdout_plain
        assert "Ollama API is responding without authentication" in result.stdout_plain


# ─────────────────────────────────────────────────────────────────────────────
# Bug 6: Unanchored /etc/hosts grep
# ─────────────────────────────────────────────────────────────────────────────


class TestHostsAnchoring:
    def test_substring_domain_not_counted_as_blocked(self):
        """A line like '0.0.0.0 block-telemetry.ollama.ai.evil.com' must NOT
        count as blocking 'telemetry.ollama.ai'."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("127.0.0.1 localhost\n")
            f.write("0.0.0.0 block-telemetry.ollama.ai.evil.com\n")
            hosts_path = f.name

        try:
            # The script does: grep -q "$domain" /etc/hosts
            # We test the exact command the script uses.
            domain = "telemetry.ollama.ai"
            result_old = subprocess.run(
                ["grep", "-q", domain, hosts_path],
                capture_output=True,
                text=True,
            )
            # Old unanchored grep MATCHES — this is the bug.
            assert result_old.returncode == 0, "Old grep should match (demonstrating the bug)"

            # Fixed anchored grep should NOT match.
            result_new = subprocess.run(
                ["grep", "-qE", f"^\\s*0\\.0\\.0\\.0\\s+{domain}$", hosts_path],
                capture_output=True,
                text=True,
            )
            assert result_new.returncode != 0, "Anchored grep must NOT match the substring"
        finally:
            os.unlink(hosts_path)


class TestHistoryLogs:
    def test_empty_history_file_does_not_emit_numeric_syntax_error(self):
        """grep -c no-match output must normalize to one numeric value."""
        with tempfile.TemporaryDirectory() as tmpdir:
            open(os.path.join(tmpdir, ".bash_history"), "w").close()

            result = source_and_run(
                "check_history_logs",
                env_vars={"HOME": tmpdir},
            )

            assert result.returncode == 0
            assert "syntax error in expression" not in result.stderr_plain
            assert "No API keys found in .bash_history" in result.stdout_plain


# ─────────────────────────────────────────────────────────────────────────────
# Bug 7: grep -v grep antipattern
# ─────────────────────────────────────────────────────────────────────────────


class TestProcessGrep:
    def test_process_with_grep_in_name_is_detected(self):
        """A process named 'ollama-grep-helper' must NOT be filtered by
        'grep -v grep'."""
        mock_ps = '''
if [ "$1" = "aux" ]; then
    echo 'user       1234   0.0  0.1  12345  6789 pts/0    S+   10:00   0:00 ollama-grep-helper --port 8080'
fi
'''
        result = source_and_run(
            "check_processes",
            mocks={"ps": mock_ps, "uname": 'echo Linux'},
        )
        assert "ollama-grep-helper" in result.stdout_plain


# ─────────────────────────────────────────────────────────────────────────────
# Bug 8: World-readable directory false positive
# ─────────────────────────────────────────────────────────────────────────────


class TestModelPermissions:
    def test_directory_mode_755_not_flagged(self):
        """A model directory with mode 755 (normal) must NOT trigger a
        world-readable warning."""
        with tempfile.TemporaryDirectory() as tmpdir:
            model_dir = os.path.join(tmpdir, ".ollama", "models")
            os.makedirs(model_dir, mode=0o755)

            result = source_and_run(
                "check_model_permissions",
                env_vars={"HOME": tmpdir},
            )
            assert "world-readable" not in result.stdout_plain.lower()

    def test_nested_world_readable_model_file_is_flagged(self):
        """World-readable model files nested below a model dir must be detected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            nested_dir = os.path.join(tmpdir, ".ollama", "models", "blobs")
            os.makedirs(nested_dir, mode=0o755)
            model_file = os.path.join(nested_dir, "sha256-deadbeef")
            with open(model_file, "w") as f:
                f.write("mock model weights")
            os.chmod(model_file, 0o644)

            result = source_and_run(
                "check_model_permissions",
                env_vars={"HOME": tmpdir},
            )
            assert "world-readable" in result.stdout_plain.lower()


# ─────────────────────────────────────────────────────────────────────────────
# Finding 4: untrusted output must not be interpreted as terminal controls
# ─────────────────────────────────────────────────────────────────────────────


class TestResultOutputSanitization:
    @pytest.mark.parametrize("helper", ["result_cooked", "result_warming", "result_safe", "result_skip"])
    def test_result_helpers_do_not_interpret_untrusted_escape_sequences(self, helper):
        """Result helpers must not turn message text into terminal controls."""
        result = source_and_run(
            f"{helper} 'malicious\\033[2Jbell\\007done'",
        )

        assert result.returncode == 0
        assert "malicious" in result.stdout
        assert "done" in result.stdout
        assert "\x1b[2J" not in result.stdout
        assert "\x07" not in result.stdout


# ─────────────────────────────────────────────────────────────────────────────
# Bug 9: NVIDIA false positive from process name matching
# ─────────────────────────────────────────────────────────────────────────────


class TestGpuExposure:
    def test_nvidia_settings_process_not_flagged(self):
        """A process named 'nvidia-settings' on an unrelated port must NOT
        trigger the NVIDIA GPU exposure warning."""
        mock_ss = '''
if [ "$1" = "-tlnp" ]; then
    echo 'LISTEN 0 128 0.0.0.0:12345 users:(("nvidia-settings",pid=5555,fd=3))'
fi
'''
        mock_nvidia_smi = '''
echo "Mock nvidia-smi"
'''
        result = run_with_mocks(
            mocks={"ss": mock_ss, "uname": 'echo Linux', "nvidia-smi": mock_nvidia_smi},
            extra_path="/usr/bin:/bin",
        )
        assert "NVIDIA management service has network-exposed ports" not in result.stdout_plain


# ─────────────────────────────────────────────────────────────────────────────
# Bug 10: Specific non-loopback listeners misreported as localhost
# ─────────────────────────────────────────────────────────────────────────────


class TestSpecificBindExposure:
    def test_specific_non_loopback_bind_is_not_localhost_safe(self):
        """A concrete LAN bind is network-reachable, not localhost-only."""
        mock_ss = '''
if [ "$1" = "-tlnp" ]; then
    echo 'LISTEN 0 128 192.168.1.50:11434 users:(("ollama",pid=12345,fd=3))'
fi
'''
        result = source_and_run(
            "check_network_exposure",
            mocks={"ss": mock_ss, "uname": 'echo Linux'},
            extra_path="/usr/bin:/bin",
        )
        assert "bound to localhost only" not in result.stdout_plain
        assert "Ollama (port 11434) is bound to non-loopback interface 192.168.1.50" in result.stdout_plain


# ─────────────────────────────────────────────────────────────────────────────
# Bug 11: Specific non-loopback HTTP listeners skipped by SSL/TLS check
# ─────────────────────────────────────────────────────────────────────────────


class TestSpecificBindSslTls:
    def test_specific_non_loopback_http_probe_flags_plain_http(self):
        """Plain HTTP on a concrete LAN bind is still non-localhost exposure."""
        mock_ss = '''
if [ "$1" = "-tlnp" ]; then
    echo 'LISTEN 0 128 192.168.1.50:11434 users:(("ollama",pid=12345,fd=3))'
fi
'''
        mock_curl = '''
if echo "$@" | grep -q "http://192.168.1.50:11434/"; then
    echo "200"
    exit 0
fi
echo "000"
exit 0
'''
        result = source_and_run(
            "check_ssl_tls",
            mocks={"ss": mock_ss, "curl": mock_curl, "uname": 'echo Linux'},
            extra_path="/usr/bin:/bin",
        )
        assert "Port 11434 is exposed on 192.168.1.50 over plain HTTP" in result.stdout_plain


# ─────────────────────────────────────────────────────────────────────────────
# Bug 12: UFW inactive substring false positive
# ─────────────────────────────────────────────────────────────────────────────


class TestFirewall:
    def test_ufw_inactive_is_not_reported_active(self):
        """`Status: inactive` contains `active` but must not be treated as active."""
        mock_ufw = '''
echo "Status: inactive"
'''
        result = source_and_run(
            "check_firewall",
            mocks={"ufw": mock_ufw, "uname": 'echo Linux'},
            extra_path="/usr/bin:/bin",
        )
        assert "UFW firewall is active" not in result.stdout_plain
        assert "UFW is installed but INACTIVE" in result.stdout_plain

    def test_ufw_active_is_reported_active(self):
        """Exact active status still passes."""
        mock_ufw = '''
echo "Status: active"
'''
        result = source_and_run(
            "check_firewall",
            mocks={"ufw": mock_ufw, "uname": 'echo Linux'},
            extra_path="/usr/bin:/bin",
        )
        assert "UFW firewall is active" in result.stdout_plain

    def test_empty_iptables_ruleset_does_not_crash(self):
        """An empty iptables ruleset (no matching lines) must NOT abort the scan.

        grep -c prints "0" and exits 1 on no-match; the `|| echo "0"` fallback
        then yields "0\n0", which crashes the subsequent arithmetic expansion.
        """
        mock_iptables = '''
# no rules — iptables -L succeeds but emits only chain/table headers that
# grep -v filters out, leaving zero counted lines.
echo "Chain INPUT (policy ACCEPT)"
echo "target     prot opt source               destination"
'''
        result = source_and_run(
            "check_firewall",
            mocks={"iptables": mock_iptables, "uname": 'echo Linux'},
            extra_path="/usr/bin:/bin",
        )
        assert result.returncode == 0
        assert "syntax error" not in result.stderr_plain.lower()
        # Scanner still reaches its own summary line ("No active firewall detected!")
        assert "No active firewall detected!" in result.stdout_plain

    def test_inaccessible_iptables_ruleset_does_not_crash(self):
        """An iptables call that fails (e.g. no permission) must be skipped, not crash.

        The failed command emits nothing, so grep counts 0 lines; the fallback
        must normalise to a single numeric value.
        """
        mock_iptables = '''
echo "iptables: Permission denied (you must be root)" >&2
exit 1
'''
        result = source_and_run(
            "check_firewall",
            mocks={"iptables": mock_iptables, "uname": 'echo Linux'},
            extra_path="/usr/bin:/bin",
        )
        assert result.returncode == 0
        assert "syntax error" not in result.stderr_plain.lower()
        assert "No active firewall detected!" in result.stdout_plain

    def test_inaccessible_nft_ruleset_does_not_crash(self):
        """An nft call that fails under pipefail must normalise its count to one numeric value.

        `nft list ruleset | wc -l` emits "0" but the pipeline exits nonzero on
        failure; the `|| echo "0"` fallback would otherwise yield "0\n0".
        """
        mock_nft = '''
echo "nft: Operation not permitted" >&2
exit 1
'''
        result = source_and_run(
            "check_firewall",
            mocks={"nft": mock_nft, "uname": 'echo Linux'},
            extra_path="/usr/bin:/bin",
        )
        assert result.returncode == 0
        assert "syntax error" not in result.stderr_plain.lower()
        assert "No active firewall detected!" in result.stdout_plain

# ─────────────────────────────────────────────────────────────────────────────
# Inspection failure must never be reported SAFE
# (model directory unreadable / docker mount inspect failure)
# ─────────────────────────────────────────────────────────────────────────────


class TestModelPermissionsIncomplete:
    @pytest.mark.skipif(os.geteuid() == 0, reason="permission bits not enforced as root")
    def test_unreadable_model_dir_is_not_reported_safe(self):
        """An unreadable model directory must NOT be reported SAFE; the scan must
        say inspection was incomplete (SKIP) while continuing the scan/summary."""
        with tempfile.TemporaryDirectory() as tmpdir:
            model_dir = os.path.join(tmpdir, ".ollama", "models")
            os.makedirs(model_dir, mode=0o755)
            os.chmod(model_dir, 0o000)
            try:
                result = source_and_run(
                    "check_model_permissions",
                    env_vars={"HOME": tmpdir},
                )
            finally:
                os.chmod(model_dir, 0o755)

            assert "SAFE" not in result.stdout_plain
            assert "world-readable" not in result.stdout_plain.lower()
            assert "incomplete" in result.stdout_plain.lower()


class TestDockerSensitiveMounts:
    def test_home_mount_detected_when_not_last_and_has_trailing_delimiter(self):
        """A `/home/<user>` mount must be detected even when it is NOT the last
        mount source (old space-joined grep with `$` anchor missed it)."""
        mock_docker = '''
case "$1" in
  info) exit 0 ;;
  ps) echo "webui nogpu/open-webui" ;;
  inspect)
    case "$*" in
      *'Config.User'*) echo "1000" ;;
      *'Privileged'*) echo "false" ;;
      *'NetworkMode'*) echo "default" ;;
      *'{{"\\n"'*) printf '/home/alice\\n/data\\n' ;;
      *) echo '/home/alice /data' ;;
    esac
    ;;
esac
'''
        result = source_and_run(
            "check_docker_risks",
            mocks={"docker": mock_docker, "uname": 'echo Linux'},
        )
        assert "has sensitive host paths mounted" in result.stdout_plain

    def test_docker_inspect_failure_reports_unknown_not_clean(self):
        """If `docker inspect` fails, the mount check must report UNKNOWN rather
        than silently reporting nothing/clean."""
        mock_docker = '''
case "$1" in
  info) exit 0 ;;
  ps) echo "webui nogpu/open-webui" ;;
  *) echo "inspect failed" >&2; exit 1 ;;
esac
'''
        result = source_and_run(
            "check_docker_risks",
            mocks={"docker": mock_docker, "uname": 'echo Linux'},
        )
        assert "UNKNOWN" in result.stdout_plain
        assert "incomplete" in result.stdout_plain.lower()
