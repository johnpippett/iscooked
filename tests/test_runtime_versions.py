"""Read-only runtime version checks against reviewed advisory minimums."""
import json
import shlex

import pytest
from test_iscooked import source_and_run


def probe(port=11434, route_bodies=None, status='200', process='ollama', host='127.0.0.1', ss=None, netstat='exit 1'):
    """Mock one listener and a curl that answers by route."""
    arms = []
    for route, body in (route_bodies or {}).items():
        payload = body if isinstance(body, str) else json.dumps(body)
        arms.append(f' *:{port}{route}*) printf "%s\\n%s" {shlex.quote(payload)} {shlex.quote(status)} ;;')
    curl = 'case "$*" in\n' + '\n'.join(arms) + '\n *) printf "\\n000"; exit 7 ;;\nesac'
    if ss is None:
        line = f'LISTEN 0 128 {host}:{port} 0.0.0.0:* users:(("{process}",pid=12,fd=3))'
        ss = 'printf "%s\\n" ' + shlex.quote(line)
    return source_and_run('check_runtime_versions; echo SCORE=$SCORE', mocks={
        'curl': curl, 'ss': ss, 'netstat': netstat, 'uname': 'echo Linux',
    })


@pytest.mark.parametrize('version,word,score', [
    ('0.34.1', 'older than 0.35.0', 4),
    ('0.35.0', 'at or above 0.35.0', 0),
    ('0.40.2', 'at or above 0.35.0', 0),
    ('0.0.0', 'development build', 4),
])
def test_ollama_version_outcomes_on_localhost(version, word, score):
    r = probe(route_bodies={'/api/version': {'version': version}})
    assert r.returncode == 0, r.stderr
    assert word in r.stdout_plain
    assert f'SCORE={score}' in r.stdout_plain


@pytest.mark.parametrize('host', ['0.0.0.0', '192.168.1.40', '[::]'])
def test_vulnerable_ollama_beyond_localhost_scores_ten(host):
    r = probe(host=host, route_bodies={'/api/version': {'version': '0.30.0'}})
    assert 'listens beyond localhost' in r.stdout_plain
    assert 'SCORE=10' in r.stdout_plain


def test_unknown_bind_with_vulnerable_version_is_warning():
    r = probe(ss='exit 1', route_bodies={'/api/version': {'version': '0.30.0'}})
    assert 'bind exposure not verified' in r.stdout_plain
    assert 'SCORE=4' in r.stdout_plain


def test_generic_version_payload_is_not_ollama():
    r = probe(process='nginx', route_bodies={'/api/version': {'version': '0.1.0', 'name': 'other'}})
    assert 'identity unconfirmed' in r.stdout_plain
    assert 'SCORE=0' in r.stdout_plain


def test_ollama_process_without_version_is_unknown():
    r = probe(status='500', route_bodies={'/api/version': {'error': 'x'}})
    assert 'version unavailable (HTTP 500)' in r.stdout_plain
    assert 'SCORE=4' in r.stdout_plain


def test_vllm_needs_process_or_model_owner():
    unconfirmed = probe(port=8000, process='python3', route_bodies={'/version': {'version': '0.10.0'}})
    assert 'identity unconfirmed' in unconfirmed.stdout_plain
    assert 'SCORE=0' in unconfirmed.stdout_plain
    by_owner = probe(port=8000, process='python3', route_bodies={
        '/version': {'version': '0.10.0'},
        '/v1/models': {'object': 'list', 'data': [{'id': 'm', 'owned_by': 'vllm'}]},
    })
    assert 'older than 0.14.1' in by_owner.stdout_plain
    assert 'SCORE=4' in by_owner.stdout_plain


@pytest.mark.parametrize('version,score', [('0.14.0', 4), ('0.14.1+cu129', 0), ('0.26.0', 0)])
def test_vllm_threshold(version, score):
    r = probe(port=8000, process='vllm', route_bodies={'/version': {'version': version}})
    assert f'SCORE={score}' in r.stdout_plain


@pytest.mark.parametrize('body,word,score', [
    ({'status': 'healthy', 'db': 'connected', 'litellm_version': '1.83.6'}, 'older than 1.83.14', 4),
    ({'status': 'healthy', 'db': 'connected', 'litellm_version': '1.83.14'}, 'at or above 1.83.14', 0),
])
def test_litellm_version_from_readiness(body, word, score):
    r = probe(port=4000, process='python3', route_bodies={'/health/readiness': body})
    assert word in r.stdout_plain
    assert f'SCORE={score}' in r.stdout_plain


def test_litellm_hidden_version_is_skip_not_safe():
    r = probe(port=4000, process='litellm', route_bodies={'/health/readiness': {'status': 'healthy', 'db': 'connected'}})
    assert 'does not publish its version' in r.stdout_plain
    assert 'SAFE' not in r.stdout_plain
    assert 'SCORE=0' in r.stdout_plain


def test_nothing_listening_is_skip():
    r = probe(ss='exit 0')
    assert 'nothing to check' in r.stdout_plain
    assert 'SCORE=0' in r.stdout_plain


def test_requests_are_bounded_read_only_and_local(tmp_path):
    logfile = tmp_path / 'calls'
    r = source_and_run('check_runtime_versions', mocks={
        'curl': 'printf "%s\\n" "$*" >> "$AUTH_LOG"; printf "\\n000"; exit 7',
        'ss': 'exit 1', 'netstat': 'exit 1', 'uname': 'echo Linux',
    }, env_vars={'AUTH_LOG': str(logfile), 'HTTP_PROXY': 'http://proxy.invalid'})
    assert r.returncode == 0
    calls = logfile.read_text().replace('\n%{http_code}', ' %{http_code}').splitlines()
    assert len(calls) == 3
    for call in calls:
        assert call.startswith('-q ')
        assert '--max-time 5' in call and '--noproxy *' in call and "--proto =http" in call
        assert 'http://127.0.0.1:' in call
        assert ' -L ' not in call and ' --data' not in call and 'Authorization' not in call


def test_discovered_hostname_never_becomes_probe_target(tmp_path):
    logfile = tmp_path / 'calls'
    r = source_and_run('check_runtime_versions', mocks={
        'ss': 'echo "LISTEN 0 128 attacker.invalid:11434 0.0.0.0:*"',
        'curl': 'printf "%s\\n" "$*" >> "$AUTH_LOG"; printf "\\n000"; exit 7',
    }, env_vars={'AUTH_LOG': str(logfile)})
    assert 'unsupported local bind address' in r.stdout_plain
    assert not logfile.exists() or 'attacker.invalid' not in logfile.read_text()


def test_missing_tools_are_explicit_skip():
    r = source_and_run('check_runtime_versions', function_mocks={
        'command_exists': '[[ "$1" != "python3" ]]',
    })
    assert 'SKIP' in r.stdout_plain and 'python3' in r.stdout_plain
