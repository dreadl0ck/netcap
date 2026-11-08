#!/usr/bin/env python3
"""Resolve a release builder from the published, digest-pinned inventory."""

import argparse
import json
from pathlib import Path
import re
import sys
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def resolve(variant, platform='linux/amd64'):
    root = Path(__file__).resolve().parents[2]
    lock = json.loads((root / "docker/builders/images.lock.json").read_text())
    if platform != 'linux/amd64' or lock['platform'] != platform:
        raise ValueError('qualified native builders support linux/amd64 only')
    image = lock["images"][variant]
    if not re.fullmatch(r"docker.io/dreadl0ck/netcap-builder:[\w.-]+@sha256:[0-9a-f]{64}", image):
        raise ValueError("builder must be a published immutable reference")
    return image


def manifest(reference):
    repository, selector = reference.removeprefix("docker.io/").split(":", 1)
    if "@" in selector:
        selector = selector.split("@", 1)[1]
    query = urlencode({"service": "registry.docker.io", "scope": f"repository:{repository}:pull"})
    with urlopen("https://auth.docker.io/token?" + query, timeout=30) as response:
        token = json.load(response)["token"]
    request = Request(f"https://registry-1.docker.io/v2/{repository}/manifests/{selector}", headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json",
    })
    try:
        with urlopen(request, timeout=30) as response:
            return response.headers["Docker-Content-Digest"], json.load(response)
    except HTTPError as error:
        if error.code == 404:
            return None
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('variant', nargs='?', choices=('alpine', 'alpine-dpi', 'ubuntu', 'ubuntu-dpi'))
    parser.add_argument('--platform', default='linux/amd64', choices=('linux/amd64',))
    parser.add_argument('--ensure-absent')
    parser.add_argument('--verify-public', action='store_true')
    args = parser.parse_args()
    if args.ensure_absent:
        if manifest(args.ensure_absent) is not None:
            sys.exit("Refusing to replace an existing candidate tag")
    elif args.verify_public:
        for variant in ("alpine", "alpine-dpi", "ubuntu", "ubuntu-dpi"):
            reference = resolve(variant)
            result = manifest(reference)
            if result is None:
                sys.exit(f"Published builder is missing: {variant}")
            digest, index = result
            assert digest == reference.split("@", 1)[1], reference
            platforms = [m["platform"] for m in index["manifests"]]
            assert {"architecture": "amd64", "os": "linux"} in platforms, platforms
            assert all(p['architecture'] == 'unknown' or (p['architecture'], p['os']) == ('amd64', 'linux') for p in platforms), platforms
            print(variant, reference)
    else:
        if not args.variant:
            parser.error('choose a builder variant or a registry operation')
        print(resolve(args.variant, args.platform))
