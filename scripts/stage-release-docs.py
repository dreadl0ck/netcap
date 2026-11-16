#!/usr/bin/env python3
"""Stage the text documentation used by every release packager."""
import argparse
import shutil
from pathlib import Path


def stage(source, destination):
    source, destination = Path(source), Path(destination)
    for path in sorted(source.rglob("*.md")):
        relative = path.relative_to(source)
        if any(part.startswith(".") for part in relative.parts):
            continue
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("source")
    parser.add_argument("destination")
    args = parser.parse_args()
    stage(args.source, args.destination)
