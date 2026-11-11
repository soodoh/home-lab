#!/usr/bin/env python3
"""Normalize a verified full-v2 restore into private files + explicit exports.

No production activation, database connection, container startup, or native archive
extraction is performed here. SQL/native archives remain inputs for their pinned
application restore tools. Historical raw-file snapshots need no normalization.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import stat

STAGE = Path('mnt/games/home-lab-backup/capture')


def normalize(root):
    root = Path(root)
    info = root.lstat()
    if root.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('private_target_required')
    source = root / STAGE
    # Check every capture ancestor before reading any restored metadata.
    # A full-v2 snapshot contains only this fixed subtree.
    parent = root
    for part in STAGE.parts:
        if parent.is_symlink() or not parent.is_dir() or {p.name for p in parent.iterdir()} != {part}:
            raise ValueError('restore_collision')
        parent = parent / part
    if source.is_symlink() or not source.is_dir():
        raise ValueError('capture_type')
    descriptor = os.open(source / 'manifest.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, encoding='utf-8') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('manifest_type')
        metadata = json.load(stream)
    if not isinstance(metadata, dict) or metadata.get('version') != 2:
        raise ValueError('unknown_capture_format')
    # Move trees without another full copy: Restic verified the bytes. Never follow
    # archive symlinks or overwrite a pre-existing staging destination.
    files = source / 'files'
    if files.is_symlink() or not files.is_dir():
        raise ValueError('files_type')
    symlinks = {}
    for current, dirs, names in os.walk(files, followlinks=False):
        for name in [*dirs, *names]:
            path = Path(current) / name
            relative = path.relative_to(files)
            if path.is_symlink():
                # Preserve the link instruction, not an active pointer outside
                # private staging. The eventual activation procedure recreates it.
                symlinks['/' + str(relative)] = os.readlink(path)
                path.unlink()
                continue
            mode = path.lstat().st_mode
            if not stat.S_ISREG(mode) and not stat.S_ISDIR(mode):
                raise ValueError('restore_special_file')
    def move_tree(folder, destination):
        for child in list(folder.iterdir()):
            target = destination / child.name
            info = child.lstat()
            if child.is_dir() and not child.is_symlink():
                if target.is_symlink() or (target.exists() and not target.is_dir()):
                    raise ValueError('restore_collision')
                target.mkdir(mode=stat.S_IMODE(info.st_mode), exist_ok=True)
                move_tree(child, target)
                if os.geteuid() == 0:
                    os.chown(target, info.st_uid, info.st_gid)
                shutil.copystat(child, target, follow_symlinks=False)
            else:
                if target.exists() or target.is_symlink():
                    raise ValueError('restore_collision')
                child.rename(target)
    move_tree(files, root)
    exports = root / 'recovery-exports'
    exports.mkdir(mode=0o700)
    for kind in ('databases', 'native'):
        folder = source / kind
        if folder.is_symlink() or not folder.is_dir():
            raise ValueError('export_type')
        folder.rename(exports / kind)
    metadata['symlinks'] = symlinks
    # Publish a new inode rather than rewriting anything supplied by the archive.
    descriptor = os.open(exports / 'manifest.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
        json.dump(metadata, stream, sort_keys=True)
        stream.write('\n')
    # Only remove the exact captured staging subtree, not an original /mnt tree.
    shutil.rmtree(source)
    return metadata


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target')
    args = parser.parse_args()
    try:
        normalize(args.target)
    except (OSError, ValueError, KeyError, TypeError):
        raise SystemExit('recovery_preparation=refused')
    print('recovery_preparation=verified format=full-v2 activation=false')
