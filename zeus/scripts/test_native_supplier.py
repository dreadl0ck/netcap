import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from native_supplier import UBUNTU_LIBRARIES, libtrace_evidence, yara_evidence


class YaraSupplierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'scripts').mkdir()
        self.pins = 'YARA_X_VERSION=1.22.0\nYARA_X_SHA256=' + 'a' * 64 + '\nYARA_X_RUST_VERSION=1.95.0\n'
        (self.root / 'scripts/yara-x.env').write_text(self.pins)
        self.library = self.root / 'libyara_x_capi.so'
        self.library.write_bytes(b'qualified supplier library')
        self.digest = hashlib.sha256(self.library.read_bytes()).hexdigest()
        self.output = self.digest + '  /usr/local/lib/libyara_x_capi.so\n1.22.0\n' + self.pins
        for recipe in ('build-yara-x.sh', 'install-yara-rust.sh'):
            (self.root / 'scripts' / recipe).write_bytes(recipe.encode())
            self.output += hashlib.sha256(recipe.encode()).hexdigest() + '  /opt/netcap-native/' + recipe + '\n'

    def evidence(self, output=None):
        with patch('native_supplier.subprocess.check_output', return_value=output or self.output):
            return yara_evidence('qualified@sha256:' + 'b' * 64, self.library, self.root)

    def test_matching_library_pins_and_recipes_provide_source_evidence(self):
        result = self.evidence()
        self.assertFalse(result['requiresSupplierEvidence'])
        self.assertEqual(result['supplierLibrarySHA256'], self.digest)
        self.assertEqual(result['sourceSHA256'], 'a' * 64)

    def test_changed_library_fails(self):
        self.library.write_bytes(b'not the supplier library')
        with self.assertRaisesRegex(ValueError, 'bytes differ'):
            self.evidence()

    def test_wrong_version_pin_or_recipe_fails(self):
        for output in (self.output.replace('1.22.0', '1.21.0', 1), self.output.replace('a' * 64, 'c' * 64),
                       self.output.replace('/opt/netcap-native/build-yara-x.sh', '/different-recipe')):
            with self.subTest(output=output), self.assertRaises(ValueError):
                self.evidence(output)


class LibtraceSupplierTests(unittest.TestCase):
    def test_matching_bytes_require_exact_recipe_source_hash_and_version(self):
        with tempfile.TemporaryDirectory() as directory:
            for name, (repo, argument, version, source_hash) in UBUNTU_LIBRARIES.items():
                library = Path(directory) / name
                library.write_bytes(b'qualified library')
                digest = hashlib.sha256(library.read_bytes()).hexdigest()
                history = argument + '=' + version + ' https://github.com/' + repo + '/archive/refs/tags/${' + argument + '}.tar.gz ' + source_hash
                with patch('native_supplier.subprocess.check_output', return_value=digest + '  /usr/local/lib/' + name):
                    self.assertFalse(libtrace_evidence('qualified-image', library, history)['requiresSupplierEvidence'])
                    for bad in (history.replace(version, '0.0.0'), history.replace(source_hash, '0' * 64), history.replace(repo, 'wrong/repo')):
                        with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'build history'):
                            libtrace_evidence('qualified-image', library, bad)
                    library.write_bytes(b'changed bytes')
                    with self.assertRaisesRegex(ValueError, 'bytes differ'):
                        libtrace_evidence('qualified-image', library, history)


if __name__ == '__main__':
    unittest.main()
