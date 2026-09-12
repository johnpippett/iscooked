"""Release metadata must stay aligned without a runtime dependency."""
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def fixture_repo(tmp_path):
    for name in ('VERSION', 'iscooked', 'site/iscooked.com', 'site/index.html', 'README.md'):
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    return tmp_path


def run_sync(root, *args):
    return subprocess.run([sys.executable, str(ROOT / 'scripts/sync_version.py'),
                           '--root', str(root), *args], capture_output=True, text=True)


def test_current_release_is_synchronized():
    result = run_sync(ROOT, '--check')
    assert result.returncode == 0, result.stdout + result.stderr


def test_bump_updates_every_surface_and_is_idempotent(tmp_path):
    root = fixture_repo(tmp_path)
    assert run_sync(root, '1.2.3').returncode == 0
    assert (root / 'VERSION').read_text() == '1.2.3\n'
    assert 'VERSION="1.2.3"' in (root / 'iscooked').read_text()
    assert (root / 'iscooked').read_bytes() == (root / 'site/iscooked.com').read_bytes()
    html = (root / 'site/index.html').read_text()
    assert '<span>v1.2.3</span>' in html
    assert 'Scanner v1.2.3</span>' in html
    assert 'version-1.2.3-blue' in (root / 'README.md').read_text()
    assert run_sync(root, '--check').returncode == 0
    before = {p: p.read_bytes() for p in root.rglob('*') if p.is_file()}
    assert run_sync(root).returncode == 0
    assert all(p.read_bytes() == body for p, body in before.items())


def test_check_detects_drift_without_writing(tmp_path):
    root = fixture_repo(tmp_path)
    page = root / 'site/index.html'
    version = (root / 'VERSION').read_text().strip()
    page.write_text(page.read_text().replace(f'Scanner v{version}', 'Scanner v0.0.1'))
    before = page.read_bytes()
    assert run_sync(root, '--check').returncode == 1
    assert page.read_bytes() == before


def test_invalid_version_and_missing_marker_do_not_partially_write(tmp_path):
    root = fixture_repo(tmp_path)
    assert run_sync(root, '1.2;bad').returncode != 0
    page = root / 'site/index.html'
    page.write_text(page.read_text().replace('hero-badge', 'removed-badge'))
    before = {p: p.read_bytes() for p in root.rglob('*') if p.is_file()}
    assert run_sync(root, '1.2.3').returncode != 0
    assert all(p.read_bytes() == body for p, body in before.items())


def test_divergent_scanners_are_not_silently_overwritten(tmp_path):
    root = fixture_repo(tmp_path)
    deployed = root / 'site/iscooked.com'
    deployed.write_text(deployed.read_text() + '\n# independent edit\n')
    before = deployed.read_bytes()
    assert run_sync(root, '1.2.3').returncode == 1
    assert deployed.read_bytes() == before
