"""Launch-only remote-code assessment; no model code or config is loaded."""
import shlex
import pytest
from test_iscooked import source_and_run


def scan(command=None, ps=None, functions=None):
    if ps is None:
        ps = 'printf "%s\\n" ' + shlex.quote('123 ' + command) if command else 'exit 0'
    return source_and_run('check_model_code_execution; echo SCORE=$SCORE',
                          mocks={'ps': ps}, function_mocks=functions)


@pytest.mark.parametrize('flag', ['--trust-remote-code', '--trust-remote-code=true', '--trust-remote-code True', '--trust-remote-code=1', '--trust-remote-code yes'])
def test_enabled(flag):
    r = scan('vllm serve secret/model ' + flag)
    assert r.returncode == 0
    assert 'allows remote model code' in r.stdout_plain
    assert 'without a verified immutable code revision' in r.stdout_plain
    assert 'SCORE=4' in r.stdout_plain
    assert 'secret/model' not in r.stdout_plain


@pytest.mark.parametrize('flag', ['--trust-remote-code=false', '--trust-remote-code False', '--trust-remote-code=0', '--no-trust-remote-code'])
def test_explicit_disabled_is_not_runtime_safety_proof(flag):
    r = scan('vllm serve model ' + flag)
    assert 'explicitly disables' in r.stdout_plain
    assert 'runtime behavior is not verified' in r.stdout_plain
    assert 'SCORE=0' in r.stdout_plain


@pytest.mark.parametrize('prefix', ['vllm serve model', '/bin/python3 -m vllm.entrypoints.openai.api_server --model model', '/usr/bin/text-generation-launcher --model-id model'])
def test_recognized_entrypoints(prefix):
    assert 'allows remote model code' in scan(prefix + ' --trust-remote-code').stdout_plain


@pytest.mark.parametrize('flag', ['--code-revision ' + 'a'*40, '--code-revision=' + 'b'*40])
def test_code_pin_keeps_warning(flag):
    r = scan('vllm serve model --trust-remote-code ' + flag)
    assert 'immutable code revision is specified' in r.stdout_plain
    assert 'Review' in r.stdout_plain and 'SCORE=4' in r.stdout_plain


@pytest.mark.parametrize('flag', ['--revision=' + 'a'*40, '--code-revision=main', '--code-revision=abc1234', '--code-revision'])
def test_weights_or_mutable_revision_not_code_pin(flag):
    r = scan('vllm serve model --trust-remote-code ' + flag)
    assert 'without a verified immutable code revision' in r.stdout_plain
    assert 'SCORE=4' in r.stdout_plain


@pytest.mark.parametrize('cmd', ['echo vllm serve --trust-remote-code', 'grep text-generation-launcher --trust-remote-code', 'python -c "vllm serve --trust-remote-code"', 'evil-vllm serve --trust-remote-code', 'vllm --help', 'cat README.md'])
def test_unrelated_commands_skip(cmd):
    r = scan(cmd)
    assert 'SKIP' in r.stdout_plain and 'SCORE=0' in r.stdout_plain


@pytest.mark.parametrize('tail', ['--config secret.yaml', '--trust-remote-code=maybe', '--trust-remote-code "unterminated'])
def test_active_unknown_preserves_four_points(tail):
    r = scan('vllm serve model ' + tail)
    assert 'could not establish' in r.stdout_plain and 'SCORE=4' in r.stdout_plain
    assert 'secret.yaml' not in r.stdout_plain


def test_failed_process_inspection():
    r = scan(ps='echo secret >&2; exit 1')
    assert 'inspection unavailable' in r.stdout_plain and 'SCORE=4' in r.stdout_plain
    assert 'secret' not in r.stdout + r.stderr


def test_missing_parser():
    r = scan(functions={'command_exists': '[[ "$1" != python3 ]]'})
    assert 'optional python3 is required' in r.stdout_plain
    assert 'SKIP' in r.stdout_plain and 'SCORE=0' in r.stdout_plain


def test_no_processes():
    assert 'SKIP' in scan().stdout_plain


def test_conflicting_flags_are_unknown():
    r = scan('vllm serve model --trust-remote-code --no-trust-remote-code')
    assert 'could not establish' in r.stdout_plain and 'SCORE=4' in r.stdout_plain


def test_tgi_weights_revision_is_not_verified_executable_code_pin():
    r = scan('text-generation-launcher --trust-remote-code --revision=' + 'a'*40)
    assert 'without a verified immutable code revision' in r.stdout_plain
    assert 'SCORE=4' in r.stdout_plain


def test_model_names_credentials_and_control_characters_are_not_printed():
    r = scan('vllm serve private/model --api-key supersecret --trust-remote-code --code-revision=\x1b[31msecret')
    assert 'SCORE=4' in r.stdout_plain
    assert 'private/model' not in r.stdout and 'supersecret' not in r.stdout and 'secret' not in r.stdout


def test_ps_byte_limit_is_unknown():
    r = scan(ps="head -c 1048577 /dev/zero | tr '\\000' x")
    assert r.returncode == 0
    assert 'inspection unavailable' in r.stdout_plain and 'SCORE=4' in r.stdout_plain


def test_ps_timeout_is_unknown():
    r = scan(ps='exec sleep 5')
    assert r.returncode == 0
    assert 'inspection unavailable' in r.stdout_plain and 'SCORE=4' in r.stdout_plain


def test_malformed_process_row_is_unknown():
    r = scan(ps='echo malformed')
    assert 'inspection unavailable' in r.stdout_plain and 'SCORE=4' in r.stdout_plain


@pytest.mark.parametrize('command', ['vllm serve model', 'text-generation-launcher --model-id model'])
def test_absent_flag_does_not_infer_runtime_setting_or_add_risk(command):
    r = scan(command)
    assert 'no explicit remote-code launch setting' in r.stdout_plain
    assert 'SKIP' in r.stdout_plain and 'SCORE=0' in r.stdout_plain
    assert 'SAFE' not in r.stdout_plain


@pytest.mark.parametrize('python', ['python', 'python3', 'python3.12'])
def test_vllm_console_script_wrapper(python):
    r = scan(f'/opt/venv/bin/{python} /opt/venv/bin/vllm serve private/model --trust-remote-code')
    assert 'allows remote model code' in r.stdout_plain
    assert 'SCORE=4' in r.stdout_plain
    assert 'private/model' not in r.stdout_plain


@pytest.mark.parametrize('command', ['python /tmp/not-vllm serve model --trust-remote-code',
    'python -c "vllm serve model --trust-remote-code"',
    'python /tmp/vllm --help'])
def test_unrelated_python_script_not_vllm_console_wrapper(command):
    assert 'SCORE=0' in scan(command).stdout_plain
