"""Read-only API authentication probes, with bounded service evidence."""
import json
import shlex

import pytest
from test_iscooked import source_and_run


def probe(status='200', body=None, process='ollama', host='127.0.0.1', port=11434, failure=0):
    if body is None:
        body = {'models': []}
    curl = f'''case "$*" in
 *:{port}/*) printf '%s\\n%s' {shlex.quote(json.dumps(body))} {shlex.quote(status)}; exit {failure} ;;
 *) printf '\\n000'; exit 7 ;;
esac'''
    line = f'LISTEN 0 128 {host}:{port} 0.0.0.0:* users:(("{process}",pid=12,fd=3))'
    return source_and_run('check_api_auth; echo SCORE=$SCORE', mocks={
        'curl': curl, 'ss': 'printf "%s\\n" ' + shlex.quote(line), 'uname': 'echo Linux',
    })


@pytest.mark.parametrize('status,word,score', [('200','accessible without authentication',4),
    ('401','requires authentication',0), ('403','denied access',0),
    ('404','inconclusive',4), ('302','redirect',4), ('500','inconclusive',4)])
def test_endpoint_outcomes(status, word, score):
    r = probe(status)
    assert r.returncode == 0, r.stderr
    assert '/api/tags' in r.stdout_plain
    assert word in r.stdout_plain
    assert f'SCORE={score}' in r.stdout_plain
    assert '(not open)' not in r.stdout_plain


def test_timeout_is_inconclusive():
    r = probe('000', failure=28)
    assert 'inconclusive' in r.stdout_plain
    assert 'SCORE=4' in r.stdout_plain


@pytest.mark.parametrize('body', ['<html>homepage</html>', {'data': []}, {'models': 'not a list'}])
def test_unknown_service_never_confirmed_from_generic_success(body):
    r = probe(body=body, process='nginx')
    assert 'accessible without authentication' not in r.stdout_plain
    assert 'SCORE=0' in r.stdout_plain


@pytest.mark.parametrize('host', ['0.0.0.0', '192.168.1.40', '[::]'])
def test_exposed_model_endpoint_scores_ten(host):
    r = probe(host=host)
    assert 'non-loopback' in r.stdout_plain
    assert 'SCORE=10' in r.stdout_plain


@pytest.mark.parametrize('port,process,owner,name', [(1234,'llmster','lmstudio','LM Studio'), (8000,'vllm','vllm','vLLM')])
def test_openai_model_routes_require_service_identity(port, process, owner, name):
    r = probe(port=port, process=process, body={'object':'list','data':[{'id':'model', 'owned_by':owner}]})
    assert name in r.stdout_plain
    assert '/v1/models' in r.stdout_plain
    assert 'SCORE=4' in r.stdout_plain


def test_generic_openai_compatible_models_are_not_lmstudio():
    r = probe(port=1234, process='python', body={'object':'list','data':[{'id':'model','owned_by':'someone'}]})
    assert 'accessible without authentication' not in r.stdout_plain
    assert 'SCORE=0' in r.stdout_plain


def test_requests_are_bounded_read_only_and_local(tmp_path):
    logfile = tmp_path / 'calls'
    r = source_and_run('check_api_auth', mocks={
        'curl': 'printf "%s\\n" "$*" >> "$AUTH_LOG"; printf "\\n000"; exit 7',
        'ss': 'exit 0', 'uname': 'echo Linux',
    }, env_vars={'AUTH_LOG': str(logfile), 'HTTP_PROXY': 'http://proxy.invalid'})
    assert r.returncode == 0
    calls = logfile.read_text().replace('\n%{http_code}', ' %{http_code}').splitlines()
    assert len(calls) == 3
    for call in calls:
        assert '--max-time 5' in call and '--connect-timeout 2' in call
        assert '--max-filesize 65536' in call and '--noproxy *' in call
        assert call.startswith('-q ')  # curlrc must not inject redirects or secrets.
        assert 'http://127.0.0.1:' in call
        assert ' -L ' not in call and ' --location ' not in call
        assert ' --data' not in call and 'Authorization' not in call
    assert all('/api/tags' in c or '/v1/models' in c for c in calls)


def test_missing_json_parser_is_explicit_skip():
    r = source_and_run('check_api_auth', function_mocks={
        'command_exists': '[[ "$1" != "python3" ]]',
    })
    assert r.returncode == 0
    assert 'SKIP' in r.stdout_plain and 'python3' in r.stdout_plain


def test_discovered_hostname_never_becomes_probe_target(tmp_path):
    logfile = tmp_path / 'calls'
    r = source_and_run('check_api_auth', mocks={
        'ss': 'echo "LISTEN 0 128 attacker.invalid:11434 0.0.0.0:*"',
        'curl': 'printf "%s\\n" "$*" >> "$AUTH_LOG"; printf "\\n000"; exit 7',
    }, env_vars={'AUTH_LOG': str(logfile)})
    assert 'unsupported local bind address' in r.stdout_plain
    assert 'attacker.invalid' not in logfile.read_text()


def test_known_service_malformed_response_is_inconclusive():
    r = probe(body={'error':'oops'})
    assert 'inconclusive' in r.stdout_plain and 'SCORE=4' in r.stdout_plain


def test_same_endpoint_wildcard_and_loopback_scored_once():
    r = source_and_run('check_api_auth; echo SCORE=$SCORE', mocks={
        'ss': '''printf '%s\n' 'LISTEN 0 128 127.0.0.1:11434 0.0.0.0:* users:(("ollama",pid=1,fd=3))' 'LISTEN 0 128 0.0.0.0:11434 0.0.0.0:* users:(("ollama",pid=1,fd=3))' ''',
        'curl': '''case "$*" in *:11434/*) printf '%s\n%s' '{"models":[]}' 200;; *) printf '\n000'; exit 7;; esac''',
    })
    assert 'SCORE=10' in r.stdout_plain
    assert r.stdout_plain.count('accessible without authentication') == 1
