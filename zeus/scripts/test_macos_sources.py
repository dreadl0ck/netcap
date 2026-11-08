import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest


class MacSourcePackagingTests(unittest.TestCase):
    def test_isolated_yara_recipes_replace_homebrew_formula_and_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts = root / 'zeus/scripts'
            scripts.mkdir(parents=True)
            script = scripts / 'package-macos-sources.py'
            shutil.copyfile(Path(__file__).with_name(script.name), script)
            sources = root / 'dist-macos-sources'
            sources.mkdir()
            archive = sources / 'yara-x-1.22.0.tar.gz'
            archive.write_bytes(b'synthetic source archive')
            record = dict(package='yara-x', version='1.22.0', archive=archive.name,
                          sha256=hashlib.sha256(archive.read_bytes()).hexdigest())
            for variant in ('dpi', 'nodpi'):
                (sources / ('inventory-' + variant + '.json')).write_text(json.dumps([record]))
            recipes = ('yara-x.env', 'build-yara-x.sh', 'install-yara-rust.sh')
            for recipe in recipes:
                (sources / recipe).write_text('synthetic recipe ' + recipe)
            command = [sys.executable, str(script), 'qualification']
            subprocess.run(command, check=True, capture_output=True)
            output = sources / 'netcap-macos-runtime-source-vqualification.tar.gz'
            first = output.read_bytes()
            with tarfile.open(output) as tar:
                members = {Path(name).name for name in tar.getnames()}
            self.assertTrue(set(recipes) <= members)
            self.assertFalse(any(name.endswith('.rb') for name in members))
            subprocess.run(command, check=True, capture_output=True)
            self.assertEqual(first, output.read_bytes())
            archive.write_bytes(b'tampered source archive')
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            archive.write_bytes(b'synthetic source archive')
            (sources / 'install-yara-rust.sh').unlink()
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)


if __name__ == '__main__':
    unittest.main()
