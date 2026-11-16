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
    def test_media_and_metadata_are_rejected(self):
        for name in ("netcap/docs/.gitbook/movie.mov", "netcap/docs/.DS_Store"):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "release.tar.gz"
                with tarfile.open(path, "w:gz") as archive:
                    member = tarfile.TarInfo(name)
                    member.size = 1
                    archive.addfile(member, io.BytesIO(b"x"))
                with self.assertRaisesRegex(ValueError, "unwanted release asset"):
                    module.check_archive(path)

    def test_staging_keeps_nested_markdown_without_media(self):
        stage_spec = importlib.util.spec_from_file_location("stage_docs", Path(__file__).with_name("stage-release-docs.py"))
        staging = importlib.util.module_from_spec(stage_spec)
        stage_spec.loader.exec_module(staging)
        with tempfile.TemporaryDirectory() as directory:
            source, destination = Path(directory) / "source", Path(directory) / "docs"
            for name in ("guide.md", "nested/topic.md", ".gitbook/movie.mov", ".gitbook/hidden.md", ".DS_Store"):
                file = source / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(b"fixture")
            staging.stage(source, destination)
            self.assertEqual(sorted(str(p.relative_to(destination)) for p in destination.rglob("*") if p.is_file()), ["guide.md", "nested/topic.md"])

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
