#!/usr/bin/env python3
"""Bundle the runtime image's ELF loader and dependency closure beside net."""
import argparse
import os
from pathlib import Path
import re
import subprocess


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
    output = subprocess.check_output(
        ["docker", "run", "--rm", "--entrypoint", "ldd", image, executable], text=True
    )
    paths, loader = dependencies(output)
    lib = destination / "lib"
    lib.mkdir()
    container = subprocess.check_output(["docker", "create", image], text=True).strip()
    try:
        for source in paths:
            subprocess.run(["docker", "cp", "-L", f"{container}:{source}", str(lib / Path(source).name)], check=True)
        subprocess.run(["docker", "cp", "-L", f"{container}:{executable}", str(lib / "net.bin")], check=True)
    finally:
        subprocess.run(["docker", "rm", container], check=True, stdout=subprocess.DEVNULL)
    launcher = destination / "net"
    launcher.write_text(
        '#!/bin/sh\nset -eu\n'
        'root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\n'
        f'exec "$root/lib/{Path(loader).name}" --library-path "$root/lib" "$root/lib/net.bin" "$@"\n'
    )
    os.chmod(launcher, 0o755)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    parser.add_argument("destination")
    parser.add_argument("--executable", default="/usr/bin/net")
    args = parser.parse_args()
    bundle(args.image, args.destination, args.executable)
