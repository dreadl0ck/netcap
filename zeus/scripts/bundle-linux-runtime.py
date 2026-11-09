#!/usr/bin/env python3
"""Bundle the runtime image's ELF loader and dependency closure beside net."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import struct


def relocate_executable(path, libraries):
    """Repoint absolute DT_NEEDED entries at their existing basename strings."""
    data = bytearray(path.read_bytes())
    if data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('expected a little-endian ELF64 executable')
    phoff = struct.unpack_from('<Q', data, 32)[0]
    phsize, phcount = struct.unpack_from('<HH', data, 54)
    headers = [struct.unpack_from('<IIQQQQQQ', data, phoff + i * phsize) for i in range(phcount)]
    dynamic = next(h for h in headers if h[0] == 2)
    entries = [(offset, *struct.unpack_from('<qQ', data, offset)) for offset in range(dynamic[2], dynamic[2] + dynamic[5], 16)]
    straddr = next(value for _, tag, value in entries if tag == 5)
    segment = next(h for h in headers if h[0] == 1 and h[3] <= straddr < h[3] + h[5])
    strings = segment[2] + straddr - segment[3]
    for offset, tag, value in entries:
        if tag not in (1, 15, 29):
            continue
        begin = strings + value
        end = data.index(0, begin)
        text = bytes(data[begin:end])
        if tag == 1 and b'/' in text:
            name = text.rsplit(b'/', 1)[1].decode()
            if name not in libraries:
                raise ValueError('absolute dependency is not bundled: ' + name)
            struct.pack_into('<Q', data, offset + 8, value + text.rindex(b'/') + 1)
        elif tag in (15, 29):
            if len(text) < len(b'$ORIGIN'):
                raise ValueError('runtime search path too short to relocate')
            data[begin:end] = b'$ORIGIN' + bytes(len(text) - len(b'$ORIGIN'))
    path.write_bytes(data)


def launcher(loader):
    return ('#!/bin/sh\nset -eu\n'
            'target=$0\n'
            'case "$target" in */*) ;; *) target=$(command -v -- "$target");; esac\n'
            'hops=0\n'
            'while [ -L "$target" ]; do\n'
            '  hops=$((hops + 1))\n'
            '  [ "$hops" -le 40 ] || { printf "%s\\n" "launcher symlink loop" >&2; exit 1; }\n'
            '  root=$(CDPATH= cd -- "$(dirname -- "$target")" && pwd)\n'
            '  target=$(readlink -- "$target")\n'
            '  case "$target" in /*) ;; *) target=$root/$target;; esac\n'
            'done\n'
            'root=$(CDPATH= cd -- "$(dirname -- "$target")" && pwd)\n'
            f'exec "$root/lib/{loader}" --library-path "$root/lib" "$root/lib/net.bin" "$@"\n')


def dependencies(output):
    if "not found" in output:
        raise ValueError("runtime image has unresolved ELF dependencies")
    paths = sorted(set(re.findall(r"(?:=>\s*|^\s*)(/[^\s()]+)", output, re.M)))
    loaders = [p for p in paths if re.search(r"/ld-(?:linux|musl)[^/]*\.so", p)]
    if len(loaders) != 1:
        raise ValueError("expected exactly one ELF interpreter")
    if len({Path(p).name for p in paths}) != len(paths):
        raise ValueError("dependency basenames collide")
    return paths, loaders[0]


def bundle(image, destination, executable="/usr/bin/net"):
    destination = Path(destination).resolve()
    if not destination.is_dir():
        raise ValueError("archive staging directory does not exist")
    platform = subprocess.check_output(["docker", "image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", image], text=True).strip()
    if platform != 'linux/amd64':
        raise ValueError('qualified runtime packaging supports linux/amd64 only')
    output = subprocess.check_output(
        ["docker", "run", "--rm", "--platform", "linux/amd64", "--cpus=2", "--network=none", "--entrypoint", "ldd", image, executable], text=True
    )
    paths, loader = dependencies(output)
    lib = destination / "lib"
    lib.mkdir()
    container = subprocess.check_output(["docker", "create", "--platform", "linux/amd64", image], text=True).strip()
    try:
        for source in paths:
            subprocess.run(["docker", "cp", "-L", f"{container}:{source}", str(lib / Path(source).name)], check=True)
        subprocess.run(["docker", "cp", "-L", f"{container}:{executable}", str(lib / "net.bin")], check=True)
    finally:
        subprocess.run(["docker", "rm", container], check=True, stdout=subprocess.DEVNULL)
    relocate_executable(lib / 'net.bin', {Path(p).name for p in paths})
    entrypoint = destination / "net"
    entrypoint.write_text(launcher(Path(loader).name))
    os.chmod(entrypoint, 0o755)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    parser.add_argument("destination")
    parser.add_argument("--executable", default="/usr/bin/net")
    args = parser.parse_args()
    bundle(args.image, args.destination, args.executable)
