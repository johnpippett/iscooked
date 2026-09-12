#!/usr/bin/env python3
"""Stamp release metadata from VERSION; downloaded scanners stay standalone."""
import argparse
from pathlib import Path
import re
import sys

SEMVER = r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)'


def replace_one(text, pattern, replacement, label):
    updated, count = re.subn(pattern, replacement, text, flags=re.MULTILINE)
    if count != 1:
        raise ValueError(f'{label}: expected one version marker, found {count}')
    return updated


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('version', nargs='?', help='new stable version, e.g. 1.2.0')
    parser.add_argument('--check', action='store_true', help='report drift without writing')
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1],
                        help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.check and args.version:
        parser.error('--check cannot be combined with a new version')
    root = args.root
    try:
        version = args.version if args.version is not None else (root / 'VERSION').read_text().strip()
        if not re.fullmatch(SEMVER, version):
            raise ValueError('use a stable MAJOR.MINOR.PATCH version, e.g. 1.1.0')
        changes = {'VERSION': version + '\n'}
        for name in ('iscooked', 'site/iscooked.com'):
            changes[name] = replace_one((root / name).read_text(), r'^VERSION="[^"\n]+"$',
                                        f'VERSION="{version}"', name)
        if changes['iscooked'] != changes['site/iscooked.com']:
            raise ValueError('scanner copies differ beyond their version; reconcile them first')
        html = (root / 'site/index.html').read_text()
        html = replace_one(html, r'(<div class="hero-badge">[^\n]*<span>)v[0-9.]+(</span>)',
                           rf'\g<1>v{version}\g<2>', 'site badge')
        changes['site/index.html'] = replace_one(
            html, r'(Local AI Security Scanner v)[0-9.]+(</span>)',
            rf'\g<1>{version}\g<2>', 'site demo')
        changes['README.md'] = replace_one(
            (root / 'README.md').read_text(), r'(img.shields.io/badge/version-)[0-9.]+(-blue)',
            rf'\g<1>{version}\g<2>', 'README badge')
        # Validate every surface before writing any of them.
        stale = [name for name, body in changes.items()
                 if not (root / name).exists() or (root / name).read_text() != body]
        if args.check:
            if stale:
                print('Version drift: ' + ', '.join(stale), file=sys.stderr)
                return 1
            print(f'All release metadata matches {version}.')
            return 0
        for name in stale:
            (root / name).write_text(changes[name])
        print(f'Version {version}: updated {len(stale)} file(s).')
        return 0
    except (OSError, ValueError) as error:
        print(f'Version sync failed: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
