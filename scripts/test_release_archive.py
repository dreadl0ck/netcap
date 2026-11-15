import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("release_archive", Path(__file__).with_name("check-release-archive.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ReleaseArchiveTests(unittest.TestCase):
    def test_actual_archive_members_determine_link_validity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "release.tar.gz"
            for include_docs in (False, True):
                with tarfile.open(path, "w:gz") as archive:
                    contents = {"netcap/README.md": b"[Install](docs/installation.md) [Protocol](docs/protocol-support.md#tcp)"}
                    if include_docs:
                        contents.update({"netcap/docs/installation.md": b"install", "netcap/docs/protocol-support.md": b"protocols"})
                    for name, data in contents.items():
                        member = tarfile.TarInfo(name)
                        member.size = len(data)
                        archive.addfile(member, io.BytesIO(data))
                if include_docs:
                    self.assertEqual(module.check_archive(path), 2)
                else:
                    with self.assertRaisesRegex(ValueError, "missing release documentation"):
                        module.check_archive(path)
