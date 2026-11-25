#!/usr/bin/env python3
"""Separate ELF debug data and normalize supplier diagnostic source paths."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess


def remap_diagnostics(path):
    # These prebuilt packages use __FILE__ in diagnostics. Keep the suffix,
    # string lengths and offsets; never rewrite code or dynamic-linker data.
    if path.name.startswith('libstdc++.so.'):
        old, new = b'/home/buildozer/aports/', b'/alpine-src'
    elif path.name == 'magika':
        old, new = b'/home/runner/', b'/magika-ci'
    else:
        return
    data = bytearray(path.read_bytes())
    if old not in data:
        return
    if data[:6] != b'\x7fELF\x02\x01':
        raise ValueError(f'{path}: expected little-endian ELF64')
    table, = struct.unpack_from('<Q', data, 40)
    size, count, names = struct.unpack_from('<HHH', data, 58)
    offsets = [table + size * index for index in range(count)]
    start, length = struct.unpack_from('<QQ', data, offsets[names] + 24)
    strings = data[start:start + length]
    replacement = new.ljust(len(old) - 1, b'_') + b'/'
    for entry in offsets:
        name, _, flags = struct.unpack_from('<IIQ', data, entry)
        section = strings[name:strings.index(0, name)]
        if section == b'.rodata' and flags & 0x7 == 0x2:
            start, length = struct.unpack_from('<QQ', data, entry + 24)
            contents = data[start:start + length]
            data[start:start + length] = contents.replace(old, replacement)
    if old in data:
        raise ValueError(f'{path}: unexpected supplier path outside .rodata')
    path.write_bytes(data)


def sha(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--debug-dir', type=Path, required=True)
    parser.add_argument('--objcopy', default='objcopy')
    parser.add_argument('--strip', default='strip')
    parser.add_argument('--inventory', type=Path)
    parser.add_argument('paths', nargs='+', type=Path)
    args = parser.parse_args()
    paths = sorted({p for path in args.paths for p in (path.iterdir() if path.is_dir() else [path])
                    if p.is_file() and not p.is_symlink()})
    args.debug_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(args.debug_dir, 0o700)
    before = {}
    for path in paths:
        with path.open('rb') as handle:
            if handle.read(4) != b'\x7fELF':
                continue
        before[path.name] = sha(path)
        subprocess.run([args.objcopy, '--only-keep-debug', path, args.debug_dir / (path.name + '.debug')], check=True)
        subprocess.run([args.strip, '--strip-unneeded', path], check=True)
        remap_diagnostics(path)
    if args.inventory:
        inventory = json.loads(args.inventory.read_text())
        for entry in inventory['files']:
            path = args.inventory.parent / entry['file']
            if entry['sha256'] != before[path.name]:
                raise ValueError(f'{path}: supplier receipt differs from pre-strip library')
            entry.update(originalSHA256=entry['sha256'], sha256=sha(path), size=path.stat().st_size)
        args.inventory.write_text(json.dumps(inventory, indent=2) + '\n')


if __name__ == '__main__':
    main()
