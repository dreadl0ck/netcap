#!/usr/bin/env python3
"""Offline policycontrol SQLite snapshot operator. Stop the owning WAF before backup/restore."""
import argparse
import contextlib
import os
import pathlib
import sqlite3
import stat


def private(path, directory=False):
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(info.st_mode) or info.st_mode & 0o077:
        raise ValueError(f'{path}: private {"directory (0700)" if directory else "regular file (0600)"} required')


def connection(path, readonly=False):
    return sqlite3.connect(path.as_uri() + ('?mode=ro' if readonly else '?mode=rw'), uri=True, timeout=0)


@contextlib.contextmanager
def owner(directory):
    private(directory, directory=True)
    lock = directory / 'policycontrol.lock'
    if not lock.exists():
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
    private(lock)
    with contextlib.closing(connection(lock)) as database:
        # This is the exact lifetime lock used by policycontrol.Service.open.
        database.execute('BEGIN EXCLUSIVE')
        try:
            yield
        finally:
            database.rollback()


def snapshot(source, destination):
    private(source)
    private(destination.parent, directory=True)
    descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    try:
        with contextlib.closing(connection(source, readonly=True)) as src:
            # Refuse a live EXCLUSIVE owner before sqlite3.backup can retry forever.
            if src.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                raise ValueError('source integrity check failed')
            with contextlib.closing(connection(destination)) as dst:
                src.backup(dst)
                if dst.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                    raise ValueError('snapshot integrity check failed')
        with destination.open('rb') as data:
            os.fsync(data.fileno())
        descriptor = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except BaseException:
        destination.unlink()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['backup', 'restore'])
    parser.add_argument('--state-dir', type=pathlib.Path, required=True)
    parser.add_argument('--snapshot', type=pathlib.Path, required=True)
    args = parser.parse_args()
    if not args.state_dir.is_absolute() or not args.snapshot.is_absolute():
        parser.error('absolute paths required')
    if args.operation == 'restore':
        args.state_dir.mkdir(mode=0o700, exist_ok=True)
    with owner(args.state_dir):
        database = args.state_dir / 'policycontrol.sqlite'
        if args.operation == 'backup':
            snapshot(database, args.snapshot)
        else:
            # Existing files, including symlinks and dangling symlinks, are refused.
            snapshot(args.snapshot, database)
    print(f'{args.operation}: consistent SQLite snapshot verified')


if __name__ == '__main__':
    main()
