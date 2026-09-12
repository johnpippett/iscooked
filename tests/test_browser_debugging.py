"""Browser identity, listener exposure, and bounded metadata inspection."""
import json
import shlex
import pytest
from test_iscooked import source_and_run

METADATA = json.dumps({'Browser': 'HeadlessChrome/123.secret', 'Protocol-Version': '1.3',
                       'webSocketDebuggerUrl': 'ws://evil.example/devtools/browser/secret'})

def check(args='--remote-debugging-port=9333', host='0.0.0.0', body=METADATA,
          process='chrome', failure='', pid=123, netstat=False):
    line = f'LISTEN 0 128 {host}:9333 0.0.0.0:* users:(("chrome",pid={pid},fd=5))'
    if netstat:
        line = f'tcp6 0 0 {host}:9333 :::* LISTEN {pid}/chrome'
    return source_and_run('check_browser_debugging; echo SCORE=$SCORE', mocks={
        'ps': 'exit 1' if failure == 'ps' else 'printf "%s\\n" ' + shlex.quote(f'123 /usr/bin/{process} {args}'),
        'ss': 'exit 1' if failure == 'listeners' or netstat else 'printf "%s\\n" ' + shlex.quote(line),
        'netstat': 'printf "%s\\n" ' + shlex.quote(line) if netstat else 'exit 1',
        'curl': 'exit 7' if failure == 'curl' else 'printf "%s" ' + shlex.quote(body),
    })

@pytest.mark.parametrize('host,score', [('0.0.0.0',10), ('[::]',10), ('127.0.0.1',0), ('[::1]',0), ('[::ffff:127.0.0.1]',0)])
def test_identified_custom_port_binding(host, score):
    r=check(host=host)
    assert r.returncode == 0, r.stderr_plain
    assert f'SCORE={score}' in r.stdout_plain
    assert 'secret' not in r.stdout_plain and 'evil.example' not in r.stdout_plain

@pytest.mark.parametrize('args', ['--remote-debugging-pipe', '--some-option=9222'])
def test_no_network_debugging_flag(args):
    r=check(args=args)
    assert 'SCORE=0' in r.stdout_plain
    assert 'COOKED' not in r.stdout_plain

@pytest.mark.parametrize('failure', ['curl','listeners','ps'])
def test_incomplete_inspection(failure):
    r=check(failure=failure)
    assert 'UNKNOWN' in r.stdout_plain
    assert 'SCORE=4' in r.stdout_plain

@pytest.mark.parametrize('body', ['{}','[]','invalid', '{"Browser":"generic server","Protocol-Version":"1.3"}', '{"Browser":"Chrome/1"}'])
def test_unidentified_metadata_is_not_browser_finding(body):
    r=check(body=body)
    assert 'SCORE=4' in r.stdout_plain
    assert 'COOKED' not in r.stdout_plain


def test_unrelated_process_does_not_trigger_even_on_debugging_port():
    r=check(process='python', args='--remote-debugging-port=9222')
    assert 'SCORE=0' in r.stdout_plain


def test_pid_mismatch_not_confirmed_browser():
    r=check(pid=456)
    assert 'SCORE=4' in r.stdout_plain


def test_separate_argument_and_netstat_ipv6():
    r=check(args='--remote-debugging-port 9333',host='::',netstat=True)
    assert 'SCORE=10' in r.stdout_plain

@pytest.mark.parametrize('bind,url', [('[::]', 'http://[::1]:9333/json/version'), ('0.0.0.0', 'http://127.0.0.1:9333/json/version'), ('[::1]', 'http://[::1]:9333/json/version')])
def test_probe_is_bounded_literal_and_config_free(bind, url):
    curl = '''
test "$1" = -q || exit 8
case "$*" in *--noproxy*--proxy*--proto*--max-redirs*--connect-timeout*--max-time*--max-filesize*) ;; *) exit 9 ;; esac
while [ "$#" -gt 0 ]; do
 if [ "$1" = --url ]; then shift; test "$1" = EXPECTED || exit 10; fi
 shift
done
printf '%s' BODY
'''.replace('EXPECTED', shlex.quote(url)).replace('BODY', shlex.quote(METADATA))
    r=source_and_run('check_browser_debugging; echo SCORE=$SCORE', mocks={
        'ps': 'echo "123 /usr/bin/chrome --remote-debugging-port=9333"',
        'ss': 'echo ' + shlex.quote(f'LISTEN 0 128 {bind}:9333 *:* users:(("chrome",pid=123,fd=5))'),
        'curl': curl})
    assert 'UNKNOWN' not in r.stdout_plain
    assert 'Verified browser' in r.stdout_plain


def test_macos_unquoted_executable_path():
    r=source_and_run('check_browser_debugging; echo SCORE=$SCORE', mocks={
        'ps': 'echo "123 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome --remote-debugging-port=9333"',
        'ss': 'exit 1',
        'netstat': 'echo "tcp6 0 0 ::1.9333 *.* LISTEN"',
        'curl': 'printf "%s" ' + shlex.quote(METADATA),
    }, env_vars={'ISCOOKED_TEST_OS_TYPE':'macos'})
    assert 'Verified browser' in r.stdout_plain
    assert 'SCORE=0' in r.stdout_plain

@pytest.mark.parametrize('missing', ['python3', 'curl'])
def test_missing_optional_dependency_skips_without_score(missing):
    r = source_and_run('check_browser_debugging; echo SCORE=$SCORE',
        mocks={'ps': 'echo "123 /usr/bin/chrome --remote-debugging-port=9333"', 'ss': 'exit 1', 'netstat': 'exit 1'},
        function_mocks={'command_exists': f'test "$1" != {missing} && command -v "$1" >/dev/null'})
    assert 'SKIP' in r.stdout_plain
    assert 'SCORE=0' in r.stdout_plain
    assert 'UNKNOWN' not in r.stdout_plain


def test_oversized_process_output_is_incomplete_inspection():
    r = source_and_run('check_browser_debugging; echo SCORE=$SCORE',
        mocks={'ps': 'head -c 4194305 /dev/zero'})
    assert 'UNKNOWN' in r.stdout_plain
    assert 'SCORE=4' in r.stdout_plain


@pytest.mark.parametrize('args', [
    "--remote-debugging-port=9333 --user-data-dir=/home/user/O'Brien",
    "--user-data-dir=/home/user/O'Brien --remote-debugging-port=9333",
])
def test_unquoted_apostrophe_keeps_browser_candidate_unknown(args):
    r = check(args=args)
    assert 'UNKNOWN' in r.stdout_plain and 'SCORE=4' in r.stdout_plain
    assert 'SKIP' not in r.stdout_plain and "O'Brien" not in r.stdout_plain


def test_unrelated_malformed_process_is_not_browser_candidate():
    r = check(process='echo', args="chrome --remote-debugging-port=9333 O'Brien")
    assert 'SKIP' in r.stdout_plain and 'SCORE=0' in r.stdout_plain
