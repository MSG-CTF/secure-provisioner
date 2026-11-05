#!/usr/bin/env python3
"""Install the reviewed Pod-only storage tools without editing game manifests."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

FILES = ('koth_storage.py', 'koth_storage_worker.py', 'koth_storage_worker.cjs', 'koth_core_egress.py', 'koth_storage_artifacts.py')
GAMES = ('jenga', 'card-battle-arena', 'grand-tour-duel', 'dependency-hell', 'pixel-smuggler', 'swanopoly')


def install(source, source_sha, game, *, prefix=Path('/')):
    if game not in GAMES or not re.fullmatch(r'[0-9a-f]{40}', source_sha):
        raise ValueError('INVALID_INSTALL_SCOPE')
    source, prefix = Path(source), Path(prefix)
    base = prefix / 'usr/local/lib/msgctf-koth-storage'
    config = prefix / 'etc/msgctf-koth-storage'
    bin_dir = prefix / 'usr/local/sbin'
    for folder in (base, config, bin_dir):
        if folder.is_symlink():
            raise ValueError('INSTALL_PATH_UNSAFE')
        folder.mkdir(parents=True, exist_ok=True)
    config.chmod(0o700)
    config_file = config / 'config.json'
    if config_file.exists() and json.loads(config_file.read_text())['game'] != game:
        raise ValueError('HOST_GAME_SCOPE_MISMATCH')
    release = base / source_sha
    if release.is_symlink():
        raise ValueError('INSTALL_PATH_UNSAFE')
    release.mkdir(mode=0o755, exist_ok=True)
    hashes = {}
    for filename in FILES:
        payload = (source / filename).read_bytes()
        target = release / filename
        if target.is_symlink() or target.exists() and target.read_bytes() != payload:
            raise ValueError('IMMUTABLE_RELEASE_CHANGED')
        if not target.exists():
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            with os.fdopen(fd, 'wb') as output:
                output.write(payload); output.flush(); os.fsync(output.fileno())
        hashes[filename] = hashlib.sha256(target.read_bytes()).hexdigest()
    manifest = {'format_version': 1, 'game': game, 'source_sha': source_sha, 'files': hashes}
    def atomic(target, payload, mode):
        fd, name = tempfile.mkstemp(dir=target.parent, prefix='.install-')
        try:
            with os.fdopen(fd, 'wb') as output:
                output.write(payload); output.flush(); os.fsync(output.fileno())
            os.chmod(name, mode); os.replace(name, target)
        finally:
            Path(name).unlink(missing_ok=True)
    atomic(config_file, json.dumps(manifest, sort_keys=True).encode(), 0o600)
    link = base / 'current'
    temporary = base / ('.current-' + source_sha)
    if temporary.is_symlink(): temporary.unlink()
    os.symlink(source_sha, temporary); os.replace(temporary, link)
    wrapper = b'#!/bin/sh\nset -eu\numask 077\nexec /usr/bin/python3 -B /usr/local/lib/msgctf-koth-storage/current/koth_storage.py "$@"\n'
    atomic(bin_dir / 'msgctf-koth-storage', wrapper, 0o755)
    atomic(bin_dir / 'msgctf-koth-core-endpoint', wrapper.replace(b'koth_storage.py', b'koth_core_egress.py'), 0o755)
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--game', required=True, choices=GAMES)
    args = parser.parse_args()
    if os.geteuid() != 0: raise SystemExit('ROOT_INSTALLER_REQUIRED')
    print(json.dumps(install(args.source_dir, args.source_sha, args.game)))
