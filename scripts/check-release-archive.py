#!/usr/bin/env python3
"""Verify README-linked Markdown documentation inside a release archive."""
import argparse
import posixpath
import re
import tarfile
from pathlib import PurePosixPath
from urllib.parse import unquote, urlsplit


def check_archive(path):
    with tarfile.open(path, "r:gz") as archive:
        files = {}
        for member in archive.getmembers():
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts:
                raise ValueError(f"unsafe archive member: {member.name}")
            if member.isfile():
                files[str(name)] = member
        readmes = sorted((name for name in files if PurePosixPath(name).name == "README.md"), key=len)
        if not readmes:
            raise ValueError("release archive has no README.md")
        readme = readmes[0]
        if files[readme].size > 1 << 20:
            raise ValueError("release README exceeds 1 MiB")
        text = archive.extractfile(files[readme]).read().decode("utf-8")
        required = set()
        for target in re.findall(r"\]\(([^\s)]+)", text):
            link = urlsplit(target)
            name = unquote(link.path)
            if not link.scheme and not link.netloc and name.startswith("docs/") and name.endswith(".md"):
                required.add(posixpath.normpath(posixpath.join(posixpath.dirname(readme), name)))
        if not required:
            raise ValueError("release README contains no local Markdown documentation links")
        missing = sorted(required - files.keys())
        if missing:
            raise ValueError("missing release documentation: " + ", ".join(missing))
        return len(required)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("archive")
    args = parser.parse_args()
    try:
        count = check_archive(args.archive)
    except (OSError, ValueError, tarfile.TarError) as error:
        parser.exit(1, f"{error}\n")
    print(f"release documentation: {count} linked Markdown files present")


if __name__ == "__main__":
    main()
