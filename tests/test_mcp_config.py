"""MCP configuration checks use local fixtures and never start servers."""
import json
import os
from pathlib import Path
import subprocess

SCRIPT = Path(__file__).resolve().parents[1] / 'site' / 'iscooked.com'


def run_check(tmp_path, data=None, mode=0o600, home_mode=0o755, filename='.mcp.json'):
    # pytest ancestors are private; open them to exercise effective traversal.
    for ancestor in [tmp_path, *tmp_path.parents]:
        if str(ancestor).startswith('/tmp/pytest-'):
            ancestor.chmod(0o755)
    home = tmp_path / 'home'
    home.mkdir(exist_ok=True)
    home.chmod(home_mode)
    work = home / 'work'
    work.mkdir(exist_ok=True)
    target = (work if filename == '.mcp.json' else home) / filename
    if data is not None:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(data if isinstance(data, str) else json.dumps(data))
        target.chmod(mode)
    source = SCRIPT.read_text().replace('main "$@"', '')
    proc = subprocess.run(['/bin/bash', '-c', source + '\ncheck_mcp_config\nprintf "SCORE=%s\\n" "$SCORE"'],
                          cwd=work, env={**os.environ, 'HOME': str(home)}, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def test_absent_config_is_skip(tmp_path):
    assert 'No supported MCP' in run_check(tmp_path)


def test_restricted_filesystem_grant(tmp_path):
    out = run_check(tmp_path, {'mcpServers': {'files': {'command': 'npx', 'args': ['-y', '@modelcontextprotocol/server-filesystem', '/tmp/project']}}})
    assert 'SCORE=0' in out
    assert 'no broad' in out


def test_home_scope_and_score(tmp_path):
    out = run_check(tmp_path, {'mcpServers': {'files': {'command': 'npx', 'args': ['@modelcontextprotocol/server-filesystem', str(tmp_path / 'home')]}}})
    assert 'entire home' in out
    assert 'SCORE=4' in out


def test_arbitrary_server_args_not_filesystem_grants(tmp_path):
    out = run_check(tmp_path, {'mcpServers': {'ordinary': {'command': '/bin/example', 'args': ['/']}}})
    assert 'SCORE=0' in out


def test_world_write_and_parent_privacy(tmp_path):
    config = {'mcpServers': {'a': {'command': 'example'}}}
    assert 'world-writable' in run_check(tmp_path, config, mode=0o666)
    assert 'SCORE=0' in run_check(tmp_path, config, mode=0o666, home_mode=0o700)


def test_group_write_is_warning(tmp_path):
    out = run_check(tmp_path, {'mcpServers': {}}, mode=0o660)
    assert 'group-writable' in out
    assert 'SCORE=4' in out


def test_credentials_never_printed_and_require_traversal(tmp_path):
    config = {'mcpServers': {'secret-name\n': {'env': {'API_KEY': 'dont-print-this'}}}}
    out = run_check(tmp_path, config, mode=0o644)
    assert 'credential-bearing' in out and 'SCORE=10' in out
    assert 'dont-print-this' not in out and 'secret-name' not in out
    assert 'SCORE=0' in run_check(tmp_path, config, mode=0o644, home_mode=0o700)


def test_malformed_and_unsupported_are_unknown(tmp_path):
    assert 'UNKNOWN' in run_check(tmp_path, '{bad-secret')
    assert 'UNKNOWN' in run_check(tmp_path, {'servers': {}})


def test_cursor_and_claude_project_entries(tmp_path):
    assert 'Cursor' in run_check(tmp_path, {'mcpServers': {}}, filename='.cursor/mcp.json')
    config = {'projects': {'sensitive-path': {'mcpServers': {'x': {'command': 'mcp-server-filesystem', 'args': ['/']}}}}}
    out = run_check(tmp_path, config, filename='.claude.json')
    assert 'filesystem root' in out
    assert 'sensitive-path' not in out


def test_oversized_config_unknown(tmp_path):
    assert 'UNKNOWN' in run_check(tmp_path, ' ' * (1048576 + 1))


def test_unreadable_config_is_unknown(tmp_path):
    assert 'UNKNOWN' in run_check(tmp_path, {'mcpServers': {}}, mode=0o000)


def test_sensitive_directory_scope(tmp_path):
    out = run_check(tmp_path, {'mcpServers': {'a': {'command': 'mcp-server-filesystem', 'args': [str(tmp_path / 'home/.ssh')]}}})
    assert 'sensitive directory' in out


def test_variable_grant_is_not_reported_safe(tmp_path):
    out = run_check(tmp_path, {'mcpServers': {'a': {'command': 'mcp-server-filesystem', 'args': ['${PROJECT_ROOT}']}}})
    assert 'UNKNOWN' in out
    assert 'no broad' not in out


def test_writable_ancestor_allows_replacement(tmp_path):
    run_check(tmp_path)
    (tmp_path / 'home').chmod(0o777)
    out = run_check(tmp_path, {'mcpServers': {}}, home_mode=0o777)
    assert 'world-writable or replaceable' in out


def test_world_write_behind_group_only_traversal_is_warning(tmp_path):
    out = run_check(tmp_path, {'mcpServers': {}}, mode=0o666, home_mode=0o750)
    assert 'group-writable' in out
    assert 'SCORE=4' in out


def test_symlink_scope_resolved(tmp_path):
    run_check(tmp_path)
    alias = tmp_path / 'alias'
    alias.symlink_to(tmp_path / 'home')
    out = run_check(tmp_path, {'mcpServers': {'a': {'command': 'mcp-server-filesystem', 'args': [str(alias)]}}})
    assert 'entire home' in out


def test_sensitive_descendant_and_duplicate_grants(tmp_path):
    grant = str(tmp_path / 'home/.ssh/keys')
    out = run_check(tmp_path, {'mcpServers': {'a': {'command': 'mcp-server-filesystem', 'args': [grant, grant]}}})
    assert 'sensitive directory' in out
    assert 'SCORE=4' in out
