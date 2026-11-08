import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("builder_image", Path(__file__).with_name("builder-image.py"))
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


class BuilderPublicationTests(unittest.TestCase):
    def test_every_builder_rejects_incompatible_platforms(self):
        for variant in ('alpine', 'alpine-dpi', 'ubuntu', 'ubuntu-dpi'):
            for platform in ('linux/arm64', 'windows/amd64', 'linux/amd64,linux/arm64'):
                with self.subTest(variant=variant, platform=platform):
                    with self.assertRaises(ValueError):
                        BUILDER.resolve(variant, platform)
        for name in ('build-alpine-docker.sh', 'build-ubuntu-docker.sh'):
            result = subprocess.run(['bash', str(ROOT / 'zeus/scripts' / name)], capture_output=True, text=True,
                                    env=dict(os.environ, NETCAP_PLATFORMS='linux/arm64'))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('linux/amd64 only', result.stderr)

    def test_runtime_defaults_match_immutable_inventory(self):
        variants = {"alpine": "alpine-dpi", "alpine-nodpi": "alpine",
                    "ubuntu": "ubuntu-dpi", "ubuntu-nodpi": "ubuntu", "service": "alpine-dpi"}
        for directory, variant in variants.items():
            with self.subTest(directory=directory):
                text = (ROOT / "docker" / directory / "Dockerfile").read_text()
                self.assertIn("ARG NETCAP_BUILDER_IMAGE=" + BUILDER.resolve(variant) + "\n", text)
                self.assertIn('FROM --platform=linux/amd64 ${NETCAP_BUILDER_IMAGE} AS builder', text)

    def test_only_not_found_means_candidate_is_absent(self):
        token = io.BytesIO(json.dumps({"token": "test-only"}).encode())
        missing = HTTPError("https://registry.invalid", 404, "missing", {}, None)
        with patch.object(BUILDER, "urlopen", side_effect=[token, missing]):
            self.assertIsNone(BUILDER.manifest("dreadl0ck/netcap-builder:test"))
        missing.close()
        for code in (401, 403, 429, 500, 503):
            with self.subTest(code=code):
                token = io.BytesIO(json.dumps({"token": "test-only"}).encode())
                error = HTTPError("https://registry.invalid", code, "unavailable", {}, None)
                with patch.object(BUILDER, "urlopen", side_effect=[token, error]):
                    with self.assertRaises(HTTPError):
                        BUILDER.manifest("dreadl0ck/netcap-builder:test")
                error.close()

    def test_shared_or_unversioned_publication_is_rejected(self):
        script = ROOT / "zeus/scripts/build-builder-images.sh"
        for version in ("", "latest", "0.15.4", "yara1.15.0-84980998-20261108"):
            with self.subTest(version=version):
                result = subprocess.run(["bash", str(script)], capture_output=True, text=True,
                                        env=dict(os.environ, BUILDER_VERSION=version, PUSH="true"))
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("docker build", result.stdout)

    def test_goreleaser_stamps_the_pinned_fork(self):
        text = (ROOT / "go.mod").read_text()
        replacement = next(line.split()[-1] for line in text.splitlines()
                           if line.startswith("replace github.com/gopacket/gopacket =>"))
        upstream = next(line.split()[1] for line in text.splitlines()
                        if line.strip().startswith("github.com/gopacket/gopacket "))
        config = (ROOT / ".goreleaser.yml").read_text()
        stamps = [word for word in config.split() if word.startswith("github.com/dreadl0ck/netcap.GopacketVersion=")]
        self.assertEqual(len(stamps), 3)
        self.assertEqual(set(stamps), {"github.com/dreadl0ck/netcap.GopacketVersion=" + upstream + "+" + replacement})


if __name__ == "__main__":
    unittest.main()
