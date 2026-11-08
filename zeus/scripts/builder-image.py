#!/usr/bin/env python3
"""Resolve a release builder from the published, digest-pinned inventory."""

import json
from pathlib import Path
import re
import sys
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def resolve(variant):
    root = Path(__file__).resolve().parents[2]
    lock = json.loads((root / "docker/builders/images.lock.json").read_text())
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
    if sys.argv[1] == "--ensure-absent":
        if manifest(sys.argv[2]) is not None:
            sys.exit("Refusing to replace an existing candidate tag")
    elif sys.argv[1] == "--verify-public":
        for variant in ("alpine", "alpine-dpi", "ubuntu", "ubuntu-dpi"):
            reference = resolve(variant)
            result = manifest(reference)
            if result is None:
                sys.exit(f"Published builder is missing: {variant}")
            digest, index = result
            assert digest == reference.split("@", 1)[1], reference
            platforms = [m["platform"] for m in index["manifests"]]
            assert {"architecture": "amd64", "os": "linux"} in platforms, platforms
            print(variant, reference)
    else:
        print(resolve(sys.argv[1]))
