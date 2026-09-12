"""Read-only Docker mount access evidence and incomplete inspection regressions."""
import shlex

import pytest

from test_iscooked import source_and_run


def docker_check(mounts='', user='1000', failure='', security='["name=seccomp,profile=builtin"]', host='', userns='', function_mocks=None):
    docker = f'''
case "$1" in
 info) printf '%s\\n' {shlex.quote(security)} ;;
 ps) {'exit 1' if failure == 'ps' else 'echo "agent ollama/ollama"'} ;;
 inspect)
  {'exit 1' if failure == 'inspect' else ':'}
  case "$*" in
   *UsernsMode*) printf '%s\\n' {shlex.quote(userns)} ;;
   *Config.User*) printf '%s\\n' {shlex.quote(user)} ;;
   *Privileged*) {'exit 1' if failure == 'privileged' else 'echo false'} ;;
   *NetworkMode*) {'exit 1' if failure == 'network' else 'echo default'} ;;
   *'range .Mounts'*) {'exit 1' if failure == 'mounts' else "printf '%s\\n' " + shlex.quote(mounts)} ;;
  esac ;;
 *) exit 88 ;;
esac
'''
    return source_and_run(
        'check_docker_risks; printf "SCORE=%s\\n" "$SCORE"',
        mocks={'docker': docker, 'uname': 'echo Linux'},
        env_vars={'DOCKER_HOST': host, 'DOCKER_CONTEXT': ''},
        function_mocks=function_mocks,
    )


@pytest.mark.parametrize('source,destination', [
    ('/var/run/docker.sock', '/var/run/docker.sock'),
    ('/run/user/1000/docker.sock', '/tmp/daemon'),
    ('/srv/docker-custom.sock', '/var/run/docker.sock'),
    ('/home/alice/custom.sock', '/run/docker.sock'),
])
def test_socket_mount_is_reported_once_without_proving_effective_access(source, destination):
    result = docker_check(f'{source}|{destination}|true|bind')
    assert result.returncode == 0, result.stderr_plain
    assert 'Docker socket mount' in result.stdout_plain
    assert 'effective daemon access' in result.stdout_plain
    assert 'SCORE=4' in result.stdout_plain
    assert 'sensitive host paths' not in result.stdout_plain


def test_read_only_socket_is_not_read_only_api():
    result = docker_check('/var/run/docker.sock|/var/run/docker.sock|false|bind')
    assert 'read-only mount does not restrict Docker API operations' in result.stdout_plain
    assert 'SCORE=4' in result.stdout_plain


def test_proxy_mount_does_not_claim_rootful_control():
    result = docker_check('/srv/docker-proxy.sock|/var/run/docker.sock|true|bind')
    assert 'proxy' in result.stdout_plain
    assert 'restrictions' in result.stdout_plain
    assert 'SCORE=4' in result.stdout_plain


@pytest.mark.parametrize('rw,score,word', [('true', 10, 'read-write'), ('false', 4, 'read-only')])
def test_host_root_mount_mode(rw, score, word):
    result = docker_check(f'/|/host|{rw}|bind')
    assert 'host root filesystem' in result.stdout_plain
    assert word in result.stdout_plain
    assert f'SCORE={score}' in result.stdout_plain


def test_host_root_unknown_mode_counts_incomplete_check():
    result = docker_check('/|/host|unknown|bind')
    assert 'UNKNOWN' in result.stdout_plain
    assert 'SCORE=4' in result.stdout_plain


def test_duplicate_socket_mount_is_not_scored_twice():
    result = docker_check('/run/docker.sock|/run/docker.sock|true|bind\n/run/docker.sock|/run/docker.sock|true|bind')
    assert 'SCORE=4' in result.stdout_plain


@pytest.mark.parametrize('mount', ['/data|/data|true|bind', '/srv/app.sock|/app/socket|true|bind'])
def test_ordinary_mounts_do_not_score(mount):
    result = docker_check(mount)
    assert 'SCORE=0' in result.stdout_plain


@pytest.mark.parametrize('failure', ['mounts', 'inspect', 'ps', 'privileged', 'network'])
def test_inspection_failure_counts_unknown_without_inventing_root(failure):
    result = docker_check(failure=failure)
    assert result.returncode == 0, result.stderr_plain
    assert 'UNKNOWN' in result.stdout_plain
    assert 'SCORE=4' in result.stdout_plain
    assert 'running as root' not in result.stdout_plain


def test_root_user_group_stays_critical():
    result = docker_check(user='0:1000')
    assert 'SCORE=10' in result.stdout_plain


def test_known_rootful_socket_in_root_container_is_critical():
    result = docker_check('/custom/daemon.sock|/engine|true|bind', user='0:1000', host='unix:///custom/daemon.sock')
    assert 'rootful Docker daemon socket' in result.stdout_plain
    assert 'SCORE=20' in result.stdout_plain


def test_known_rootless_socket_in_root_container_stays_warning():
    result = docker_check('/custom/daemon.sock|/engine|true|bind', user='root', host='unix:///custom/daemon.sock', security='["name=rootless"]')
    assert 'rootless daemon' in result.stdout_plain
    assert 'SCORE=14' in result.stdout_plain


@pytest.mark.parametrize('security,userns', [
    ('["name=userns"]', ''),
    ('["name=seccomp,profile=builtin"]', 'private'),
    ('malformed', ''),
])
def test_isolation_or_incomplete_security_options_do_not_prove_rootful_access(security, userns):
    result = docker_check('/run/docker.sock|/engine|true|bind', user='root',
                          host='unix:///run/docker.sock', security=security, userns=userns)
    assert 'rootful Docker daemon socket' not in result.stdout_plain
    assert 'SCORE=14' in result.stdout_plain


def test_remote_daemon_does_not_identify_mounted_local_socket():
    result = docker_check('/run/docker.sock|/engine|true|bind', user='root', host='tcp://remote:2375')
    assert 'rootful Docker daemon socket' not in result.stdout_plain
    assert 'SCORE=14' in result.stdout_plain


def test_confirmed_rootful_read_only_socket_retains_daemon_control_risk():
    result = docker_check('/run/docker.sock|/engine|false|bind', user='root', host='unix:///run/docker.sock')
    assert 'rootful Docker daemon socket' in result.stdout_plain
    assert 'mode does not restrict API operations' in result.stdout_plain
    assert 'SCORE=20' in result.stdout_plain


def test_named_proxy_even_at_active_endpoint_does_not_claim_unrestricted_control():
    result = docker_check('/run/docker-proxy.sock|/engine|true|bind', user='root', host='unix:///run/docker-proxy.sock')
    assert 'restrictions unverified' in result.stdout_plain
    assert 'SCORE=14' in result.stdout_plain


def test_python_timeout_fallback_runs_read_only_docker_metadata():
    result = source_and_run(
        'docker_read_metadata info',
        mocks={'docker': 'test "$1" = info && echo metadata'},
        function_mocks={'command_exists': 'case "$1" in timeout|gtimeout) return 1 ;; *) command -v "$1" >/dev/null ;; esac'},
    )
    assert result.returncode == 0, result.stderr_plain
    assert result.stdout_plain.strip() == 'metadata'


@pytest.mark.parametrize('security', ['[malformed]', '[null]', '["name=seccomp",null]', '[1]', '{"security":[]}'])
def test_invalid_security_array_cannot_establish_rootful_mode(security):
    result = docker_check('/run/docker.sock|/engine|true|bind', user='root',
                          host='unix:///run/docker.sock', security=security)
    assert 'rootful Docker daemon socket' not in result.stdout_plain
    assert 'SCORE=14' in result.stdout_plain


def test_same_socket_source_at_distinct_destinations_scores_once():
    result = docker_check('/run/docker.sock|/one|false|bind\n/run/docker.sock|/two|true|bind')
    assert 'SCORE=4' in result.stdout_plain
    assert result.stdout_plain.count('Docker socket mount') == 1


@pytest.mark.parametrize('records', [
    '/|/readonly|false|bind\n/|/writable|true|bind',
    '/|/writable|true|bind\n/|/readonly|false|bind',
])
def test_host_root_repeated_source_reports_strongest_access_once(records):
    result = docker_check(records)
    assert 'SCORE=10' in result.stdout_plain
    assert result.stdout_plain.count('host root filesystem') == 1
    assert "'/writable' read-write" in result.stdout_plain


def test_unsupported_mount_type_is_incomplete_not_host_root_access():
    result = docker_check('/|/host|true|unexpected')
    assert 'UNKNOWN' in result.stdout_plain
    assert 'SCORE=4' in result.stdout_plain
    assert 'read-write' not in result.stdout_plain



def test_missing_json_parser_cannot_establish_rootful_mode():
    result = docker_check('/run/docker.sock|/engine|true|bind', user='root',
        host='unix:///run/docker.sock', function_mocks={
            'command_exists': 'case "$1" in python3) return 1 ;; *) command -v "$1" >/dev/null ;; esac'
        })
    assert 'rootful Docker daemon socket' not in result.stdout_plain
    assert 'SCORE=14' in result.stdout_plain


def test_tmpfs_is_not_host_path_access():
    result = docker_check('|/tmp|true|tmpfs')
    assert 'SCORE=0' in result.stdout_plain


def test_distinct_sensitive_paths_keep_existing_single_warning():
    result = docker_check('/etc|/etc|false|bind\n/root|/root|false|bind')
    assert 'SCORE=4' in result.stdout_plain
