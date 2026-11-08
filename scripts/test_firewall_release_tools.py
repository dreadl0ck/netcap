import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

import firewall_release_tools as tools
import firewall_download as download


class ReleaseToolAssets(unittest.TestCase):
    def test_platform_asset_names_and_checksum_verification(self):
        for system, machine, arch, goreleaser_arch in (
            ('Linux', 'x86_64', 'amd64', 'x86_64'),
            ('Linux', 'aarch64', 'arm64', 'arm64'),
            ('Darwin', 'x86_64', 'amd64', 'x86_64'),
            ('Darwin', 'arm64', 'arm64', 'arm64'),
        ):
            with self.subTest(system=system, machine=machine), tempfile.TemporaryDirectory() as tmp:
                fixtures = {}
                expected = {}
                for tool, repo, name, sums in (
                    ('syft', 'anchore/syft', f'syft_{tools.POLICY["tools"]["syft"][1:]}_{system.lower()}_{arch}.tar.gz', f'syft_{tools.POLICY["tools"]["syft"][1:]}_checksums.txt'),
                    ('goreleaser', 'goreleaser/goreleaser', f'goreleaser_{system}_{goreleaser_arch}.tar.gz', 'checksums.txt'),
                    ('helm', None, f'helm-{tools.POLICY["tools"]["helm"]}-{system.lower()}-{arch}.tar.gz', None),
                ):
                    tag = tools.POLICY['tools'][tool]
                    base = f'https://github.com/{repo}/releases/download/{tag}/' if repo else 'https://get.helm.sh/'
                    payload = f'{system}/{machine}/{tool}'.encode()
                    archive = io.BytesIO()
                    with tarfile.open(fileobj=archive, mode='w:gz') as tf:
                        info = tarfile.TarInfo(f'dist/{tool}')
                        info.size = len(payload)
                        tf.addfile(info, io.BytesIO(payload))
                    data = archive.getvalue()
                    fixtures[base + name] = data
                    fixtures[base + (sums or name + '.sha256sum')] = (hashlib.sha256(data).hexdigest() + '  ' + name + '\n').encode()
                    expected[tool] = payload

                def fetch(url, timeout):
                    self.assertIn(url, fixtures, 'installer requested a nonexistent architecture asset')
                    return io.BytesIO(fixtures[url])

                with patch.object(tools.platform, 'system', return_value=system), patch.object(tools.platform, 'machine', return_value=machine), patch.object(tools.urllib.request, 'urlopen', side_effect=fetch):
                    destination = Path(tmp) / 'tools'
                    tools.install(destination)
                for tool, payload in expected.items():
                    self.assertEqual((destination / tool).read_bytes(), payload)
                    self.assertEqual((destination / tool).stat().st_mode & 0o777, 0o755)

    def test_missing_checksum_refuses_download(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(tools.platform, 'system', return_value='Linux'), patch.object(tools.platform, 'machine', return_value='x86_64'), patch.object(tools.urllib.request, 'urlopen', return_value=io.BytesIO(b'0  different.tar.gz\n')) as fetch:
            with self.assertRaisesRegex(ValueError, 'missing upstream checksum'):
                tools.install(Path(tmp))
            self.assertEqual(fetch.call_count, 1)
            self.assertFalse(list(Path(tmp).iterdir()))

    def test_checksum_504_recovers_but_bad_archive_is_not_retried(self):
        tag = tools.POLICY['tools']['syft']
        base = f'https://github.com/anchore/syft/releases/download/{tag}/'
        name = f'syft_{tag[1:]}_linux_amd64.tar.gz'
        sums = base + f'syft_{tag[1:]}_checksums.txt'
        error = urllib.error.HTTPError(sums, 504, 'timeout', {}, io.BytesIO())
        responses = [error, io.BytesIO(('0' * 64 + '  ' + name + '\n').encode()), io.BytesIO(b'bad archive')]
        with tempfile.TemporaryDirectory() as tmp, patch.object(tools.platform, 'system', return_value='Linux'), \
                patch.object(tools.platform, 'machine', return_value='x86_64'), \
                patch.object(tools.urllib.request, 'urlopen', side_effect=responses) as fetch, \
                patch.object(download.time, 'sleep'):
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                tools.install(Path(tmp))
            self.assertEqual([c.args[0] for c in fetch.call_args_list], [sums, sums, base + name])
            self.assertFalse(list(Path(tmp).iterdir()))

    def test_invalid_archive_layout_is_not_retried(self):
        tag = tools.POLICY['tools']['syft']
        name = f'syft_{tag[1:]}_linux_amd64.tar.gz'
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w:gz'):
            pass
        payload = data.getvalue()
        responses = [io.BytesIO((hashlib.sha256(payload).hexdigest() + '  ' + name).encode()), io.BytesIO(payload)]
        with tempfile.TemporaryDirectory() as tmp, patch.object(tools.platform, 'system', return_value='Linux'), \
                patch.object(tools.platform, 'machine', return_value='x86_64'), \
                patch.object(tools.urllib.request, 'urlopen', side_effect=responses) as fetch:
            with self.assertRaisesRegex(ValueError, 'archive layout'):
                tools.install(Path(tmp))
            self.assertEqual(fetch.call_count, 2)
            self.assertFalse(list(Path(tmp).iterdir()))

    def test_oversized_checksum_response_is_not_retried(self):
        response = io.BytesIO()
        response.headers = {'Content-Length': str(download.CHECKSUM_LIMIT + 1)}
        with tempfile.TemporaryDirectory() as tmp, patch.object(tools.platform, 'system', return_value='Linux'), \
                patch.object(tools.platform, 'machine', return_value='x86_64'), \
                patch.object(tools.urllib.request, 'urlopen', return_value=response) as fetch:
            with self.assertRaisesRegex(ValueError, 'byte limit'):
                tools.install(Path(tmp))
            fetch.assert_called_once()
            self.assertTrue(response.closed)
            self.assertFalse(list(Path(tmp).iterdir()))


if __name__ == '__main__':
    unittest.main()
