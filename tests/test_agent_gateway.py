"""Read-only OpenClaw configuration audit regression fixtures."""
import json
import os
from pathlib import Path
import subprocess

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / 'site' / 'iscooked.com'


def run_check(tmp_path, config=None, *, explicit=False, kind=None, mode=0o600, no_python=False):
    home = tmp_path / 'home'
    home.mkdir(exist_ok=True)
    path = home / '.openclaw' / 'openclaw.json'
    path.parent.mkdir(exist_ok=True)
    if explicit:
        path = home / 'custom.json'
    if kind == 'fifo':
        os.mkfifo(path)
    elif kind == 'symlink':
        path.symlink_to(home / 'missing')
    elif config is not None:
        if path.exists():
            path.chmod(0o600)
        path.write_text(config if isinstance(config, str) else json.dumps(config))
        path.chmod(mode)
    env = {k: v for k, v in os.environ.items() if not k.startswith('OPENCLAW_')}
    env['HOME'] = str(home)
    if explicit:
        env['OPENCLAW_CONFIG_PATH'] = str(path)
    source = SCRIPT.read_text().replace('main "$@"', '')
    if no_python:
        source += '\ncommand() { return 1; }\n'
    proc = subprocess.run(['/bin/bash', '-c', source + '\ncheck_agent_gateway\nprintf "SCORE=%s\\n" "$SCORE"'],
                          env=env, cwd=home, capture_output=True, text=True, timeout=5)
    assert proc.returncode == 0, proc.stderr
    assert 'command not found' not in proc.stderr
    return proc.stdout


def powerful():
    return {'tools': {'profile': 'full', 'exec': {'mode': 'full', 'host': 'gateway'}},
            'agents': {'defaults': {'sandbox': {'mode': 'off'}}},
            'channels': {'telegram': {'dmPolicy': 'open', 'allowFrom': ['*']}}}


def test_absent_and_missing_python_skip(tmp_path):
    assert 'SKIP' in run_check(tmp_path)
    assert 'SKIP' in run_check(tmp_path, no_python=True)


@pytest.mark.parametrize('bind', ['lan', 'custom'])
def test_exposure_without_auth(tmp_path, bind):
    out = run_check(tmp_path, {'gateway': {'bind': bind, 'customBindHost': '10.0.0.4', 'auth': {'mode': 'none'}}})
    assert 'COOKED' in out and 'SCORE=10' in out


@pytest.mark.parametrize('auth', ['token', 'password', 'trusted-proxy'])
def test_auth_config_is_not_effective_enforcement(tmp_path, auth):
    out = run_check(tmp_path, {'gateway': {'bind': 'lan', 'auth': {'mode': auth, 'token': 'SECRET-CANARY'}}})
    assert 'COOKED' not in out and 'SCORE=0' in out and 'SECRET-CANARY' not in out
    assert 'runtime' in out


@pytest.mark.parametrize('config', [{}, {'gateway': {'bind': 'loopback', 'auth': {'mode': 'none'}}},
                                    {'gateway': {'bind': 'custom', 'customBindHost': '127.0.0.2', 'auth': {'mode': 'none'}}}])
def test_defaults_and_loopback_not_unsafe(tmp_path, config):
    assert 'SCORE=0' in run_check(tmp_path, config)


def test_open_ingress_and_powerful_tools_combined_once(tmp_path):
    out = run_check(tmp_path, powerful())
    assert 'COOKED' in out and 'SCORE=10' in out


@pytest.mark.parametrize('policy', ['pairing', 'allowlist', 'disabled'])
def test_restricted_ingress_is_warning_only(tmp_path, policy):
    config = powerful()
    config['channels']['telegram']['dmPolicy'] = policy
    out = run_check(tmp_path, config)
    assert 'COOKED' not in out and 'SCORE=4' in out


@pytest.mark.parametrize('change', ['minimal', 'deny', 'disabled_channel', 'no_wildcard', 'sandbox'])
def test_capability_or_ingress_controls_prevent_critical(tmp_path, change):
    config = powerful()
    if change == 'minimal': config['tools']['profile'] = 'minimal'
    if change == 'deny': config['tools']['deny'] = ['e*']
    if change == 'disabled_channel': config['channels']['telegram']['enabled'] = False
    if change == 'no_wildcard': config['channels']['telegram']['allowFrom'] = ['123']
    if change == 'sandbox': config['agents']['defaults']['sandbox']['mode'] = 'all'; config['tools']['exec']['host'] = 'sandbox'
    assert 'COOKED' not in run_check(tmp_path, config)


@pytest.mark.parametrize('config', ['{bad SECRET-CANARY', '{gateway: {bind: \'lan\'},}',
                                    '{"gateway":{},"gateway":{}}', '[]', {'gateway': {'auth': {'mode': 'future'}}},
                                    {'$include': '/tmp/SECRET-CANARY'}, {'tools': {'exec': {'mode': 'future'}}}])
def test_unsupported_unknown_secret_safe(tmp_path, config):
    out = run_check(tmp_path, config)
    assert 'UNKNOWN' in out and 'SCORE=4' in out and 'SECRET-CANARY' not in out


@pytest.mark.parametrize('kind', ['fifo', 'symlink'])
def test_special_paths_never_hang(tmp_path, kind):
    assert 'UNKNOWN' in run_check(tmp_path, kind=kind)


def test_unreadable_and_large(tmp_path):
    assert 'UNKNOWN' in run_check(tmp_path, {}, mode=0)
    assert 'UNKNOWN' in run_check(tmp_path, ' ' * 1048577)


def test_explicit_config_path(tmp_path):
    assert 'COOKED' in run_check(tmp_path, {'gateway': {'bind': 'lan', 'auth': {'mode': 'none'}}}, explicit=True)


def test_legacy_exec_fields(tmp_path):
    config = powerful()
    config['tools']['exec'] = {'host': 'gateway', 'security': 'full', 'ask': 'off'}
    assert 'SCORE=10' in run_check(tmp_path, config)


def test_agent_override_incomplete_not_critical(tmp_path):
    config = powerful()
    config['agents']['entries'] = {'safe': {'tools': {'profile': 'minimal'}}}
    out = run_check(tmp_path, config)
    assert 'UNKNOWN' in out and 'COOKED' not in out


def test_config_commands_are_never_executed(tmp_path):
    marker = tmp_path / 'executed'
    out = run_check(tmp_path, {'gateway': {'auth': {'token': '$(touch ' + str(marker) + ')'}},
                               'tools': {'exec': {'pathPrepend': ['$(touch ' + str(marker) + ')']}}})
    assert not marker.exists()
    assert str(marker) not in out and 'touch' not in out


@pytest.mark.parametrize('config', [
    {'gateway': {'bind': 'tailnet', 'auth': {'mode': 'none'}}},
    {'gateway': {'bind': 'auto', 'auth': {'mode': 'none'}}},
    {'tools': {'exec': {'mode': 'full', 'ask': 'always'}}},
    {'tools': {'allow': 'exec'}},
    {'channels': {'telegram': {'accounts': {}}}},
])
def test_runtime_dependent_or_unsupported_policy_unknown(tmp_path, config):
    out = run_check(tmp_path, config)
    assert 'UNKNOWN' in out and 'COOKED' not in out


@pytest.mark.parametrize('profile', ['minimal', 'messaging'])
def test_additive_exec_grant_enables_critical_combination(tmp_path, profile):
    config = powerful()
    config['tools']['profile'] = profile
    config['tools']['alsoAllow'] = ['exec']
    out = run_check(tmp_path, config)
    assert 'COOKED' in out and 'SCORE=10' in out


@pytest.mark.parametrize('profile', ['minimal', 'messaging'])
def test_restricted_profile_without_additive_exec_stays_noncritical(tmp_path, profile):
    config = powerful()
    config['tools']['profile'] = profile
    out = run_check(tmp_path, config)
    assert 'COOKED' not in out and 'SCORE=4' in out


def test_additive_exec_grant_still_respects_deny(tmp_path):
    config = powerful()
    config['tools'].update(profile='messaging', alsoAllow=['exec'], deny=['group:runtime'])
    out = run_check(tmp_path, config)
    assert 'COOKED' not in out and 'SCORE=4' in out


def test_allow_does_not_expand_restricted_base_profile(tmp_path):
    config = powerful()
    config['tools'].update(profile='messaging', allow=['exec'])
    out = run_check(tmp_path, config)
    assert 'COOKED' not in out and 'SCORE=4' in out
