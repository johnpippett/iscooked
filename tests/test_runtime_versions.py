"""Read-only runtime version checks against reviewed advisory minimums."""
import json
import shlex

import pytest
from test_iscooked import SCRIPT_PATH, source_and_run

# Keep network-probe tests independent of whatever Python packages and Docker
# images the machine running the suite happens to have.
NO_LOCAL_PACKAGES = {'litellm_package_findings': ':', 'litellm_image_findings': ':'}


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
    }, function_mocks=NO_LOCAL_PACKAGES)


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
    }, env_vars={'AUTH_LOG': str(logfile), 'HTTP_PROXY': 'http://proxy.invalid'},
        function_mocks=NO_LOCAL_PACKAGES)
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


# ── LiteLLM supply-chain compromise (PyPI 1.82.7, 1.82.8 and 1.107.0) ──────────


@pytest.mark.parametrize('version,score', [('1.107.0', 10), ('1.82.8', 10), ('v1.107.0', 10), ('1.107.0rc2', 0)])
def test_litellm_proxy_reporting_compromised_release_is_cooked_even_on_localhost(version, score):
    r = probe(port=4000, process='litellm', route_bodies={
        '/health/readiness': {'status': 'healthy', 'db': 'connected', 'litellm_version': version},
    })
    assert f'SCORE={score}' in r.stdout_plain
    if score:
        assert 'credential-stealing malware' in r.stdout_plain
        assert '1.106.2' in r.stdout_plain


def test_hidden_litellm_version_mentions_compromised_releases():
    r = probe(port=4000, process='litellm', route_bodies={'/health/readiness': {'status': 'healthy', 'db': 'connected'}})
    assert '1.107.0' in r.stdout_plain


def local_scan(tmp_path, files=(), docker=None):
    """Run check 17 with nothing listening and a fake home holding the given files."""
    home = tmp_path / 'home'
    for rel, content in files:
        path = home / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if content is None:
            path.mkdir()
        else:
            path.write_text(content)
    tmp = tmp_path / 'tmp'
    tmp.mkdir()
    mocks = {'ss': 'exit 0', 'uname': 'echo Linux', 'curl': 'exit 7'}
    if docker is not None:
        mocks['docker'] = docker
    else:
        mocks['docker'] = 'exit 1'
    return source_and_run('check_runtime_versions; echo SCORE=$SCORE', mocks=mocks,
                          env_vars={'HOME': str(home), 'TMPDIR': str(tmp)}), tmp


SITE = '.local/lib/python3.12/site-packages'


def test_dropped_pth_file_is_cooked(tmp_path):
    r, _ = local_scan(tmp_path, [(f'{SITE}/cook.pth', 'import cook\n'), (f'{SITE}/cook.py', 'x = 1\n')])
    assert 'malware file found: ~/.local/lib/python3.12/site-packages/cook.pth' in r.stdout_plain
    assert 'rotate every credential' in r.stdout_plain
    assert 'SCORE=10' in r.stdout_plain


def test_march_pth_file_is_cooked(tmp_path):
    r, _ = local_scan(tmp_path, [(f'projects/agent/.venv/lib/python3.11/site-packages/litellm_init.pth', 'import os\n')])
    assert 'litellm_init.pth' in r.stdout_plain
    assert 'SCORE=10' in r.stdout_plain


def test_unrelated_cook_pth_is_ignored(tmp_path):
    r, _ = local_scan(tmp_path, [(f'{SITE}/cook.pth', '/opt/cookbook/lib\n')])
    assert 'malware' not in r.stdout_plain
    assert 'nothing to check' in r.stdout_plain
    assert 'SCORE=0' in r.stdout_plain


def test_marker_file_in_temp_dir_is_cooked(tmp_path):
    home = tmp_path / 'home'
    home.mkdir()
    tmp = tmp_path / 'tmp'
    tmp.mkdir()
    (tmp / 'remote_code_loader.lock').write_text('')
    r = source_and_run('check_runtime_versions; echo SCORE=$SCORE', mocks={
        'ss': 'exit 0', 'uname': 'echo Linux', 'curl': 'exit 7', 'docker': 'exit 1',
    }, env_vars={'HOME': str(home), 'TMPDIR': str(tmp)})
    assert 'remote_code_loader.lock' in r.stdout_plain
    assert 'SCORE=10' in r.stdout_plain


@pytest.mark.parametrize('entry', ['litellm-1.107.0.dist-info', 'litellm-1.82.7-py3.11.egg-info'])
def test_installed_compromised_release_is_cooked(tmp_path, entry):
    r, _ = local_scan(tmp_path, [(f'.venv/lib/python3.11/site-packages/{entry}', None)])
    assert 'Compromised LiteLLM release' in r.stdout_plain
    assert 'SCORE=10' in r.stdout_plain


@pytest.mark.parametrize('entry', ['litellm-1.106.2.dist-info', 'litellm-1.107.0rc1.dist-info'])
def test_installed_clean_release_is_safe(tmp_path, entry):
    r, _ = local_scan(tmp_path, [(f'{SITE}/{entry}', None)])
    assert 'not a compromised release' in r.stdout_plain
    assert 'nothing to check' not in r.stdout_plain
    assert 'SCORE=0' in r.stdout_plain


def test_compromised_docker_image_tag_is_cooked(tmp_path):
    docker = 'printf "%s\\n" "ghcr.io/berriai/litellm-database:v1.106.2" "docker.io/litellm/litellm:v1.107.0"'
    r, _ = local_scan(tmp_path, docker=docker)
    assert 'v1.107.0 in docker image docker.io/litellm/litellm:v1.107.0' in r.stdout_plain
    assert 'SCORE=10' in r.stdout_plain


def test_local_scan_runs_without_curl(tmp_path):
    r = source_and_run('check_runtime_versions; echo SCORE=$SCORE', function_mocks={
        'command_exists': '[[ "$1" != "curl" ]]',
        'litellm_package_findings': 'printf "bad\\t1.107.0\\t~/x/litellm-1.107.0.dist-info\\n"',
        'litellm_image_findings': ':',
    })
    assert 'curl is required' in r.stdout_plain
    assert 'SCORE=10' in r.stdout_plain


def test_scanner_python_never_processes_site_packages_pth_files():
    """A compromised wheel's .pth runs on every interpreter start unless site is disabled."""
    text = open(SCRIPT_PATH).read()
    invocations = text.count('python3 -I')
    assert invocations > 0
    assert text.count('python3 -I -B -S') == invocations


# ── Pre-release builds of a minimum version are below that minimum ────────────


@pytest.mark.parametrize('version,score', [
    ('0.35.0-rc1', 4), ('0.35.0-rc.2', 4), ('0.35.0-beta', 4),
    ('0.35.0', 0), ('0.35.1-rc1', 0),
])
def test_ollama_prerelease_of_minimum_is_older(version, score):
    r = probe(route_bodies={'/api/version': {'version': version}})
    assert f'SCORE={score}' in r.stdout_plain
    if score:
        assert f'{version}, older than 0.35.0' in r.stdout_plain


@pytest.mark.parametrize('version,score', [
    ('0.14.1rc1', 4), ('0.14.1a2', 4), ('0.14.1b1', 4), ('0.14.1.dev42+g1234abc', 4),
    ('0.14.1rc1+cu129', 4), ('0.14.1+cu129', 0), ('0.14.1.post1', 0), ('0.14.2rc1', 0),
])
def test_vllm_prerelease_of_minimum_is_older(version, score):
    r = probe(port=8000, process='vllm', route_bodies={'/version': {'version': version}})
    assert f'SCORE={score}' in r.stdout_plain
    if score:
        assert f'{version}, older than 0.14.1' in r.stdout_plain


def test_litellm_prerelease_of_minimum_is_older():
    r = probe(port=4000, process='litellm', route_bodies={
        '/health/readiness': {'status': 'healthy', 'db': 'connected', 'litellm_version': '1.83.14rc1'},
    })
    assert 'older than 1.83.14' in r.stdout_plain
    assert 'SCORE=4' in r.stdout_plain


# ── LiteLLM Docker tag styles around the compromised release ──────────────────


@pytest.mark.parametrize('tag', [
    'v1.107.0', 'main-v1.107.0', 'v1.107.0-stable', 'main-v1.107.0-stable',
    'v1.107.0-nightly', 'litellm_stable_release_branch-v1.107.0-stable',
])
def test_compromised_docker_image_tag_styles_are_cooked(tmp_path, tag):
    ref = f'ghcr.io/berriai/litellm:{tag}'
    r, _ = local_scan(tmp_path, docker=f'printf "%s\\n" {shlex.quote(ref)}')
    assert f'v1.107.0 in docker image {ref}' in r.stdout_plain
    assert 'SCORE=10' in r.stdout_plain


@pytest.mark.parametrize('tag', [
    'v1.107.0rc1', 'v1.107.0-rc1', 'main-v1.107.0.rc2', 'v1.107.01', 'v1.107.0.1',
    'v1.107.00-stable', 'v11.107.0', 'v1.1107.0', 'main-v1.106.2-stable', 'main-stable',
])
def test_unrelated_docker_image_tags_are_not_cooked(tmp_path, tag):
    ref = f'ghcr.io/berriai/litellm:{tag}'
    r, _ = local_scan(tmp_path, docker=f'printf "%s\\n" {shlex.quote(ref)}')
    assert 'docker image' not in r.stdout_plain
    assert 'SCORE=0' in r.stdout_plain
