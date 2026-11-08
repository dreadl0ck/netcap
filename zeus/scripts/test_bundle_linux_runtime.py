import importlib.util
from pathlib import Path
import unittest
import tempfile
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("bundle", Path(__file__).with_name("bundle-linux-runtime.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RuntimeDependencies(unittest.TestCase):
    def test_incompatible_image_fails_before_launch_or_copy(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(module.subprocess, 'check_output', return_value='linux/arm64\n') as execute:
            with self.assertRaisesRegex(ValueError, 'linux/amd64 only'):
                module.bundle('test-only:arm64', directory)
            self.assertEqual(execute.call_count, 1)

    def test_glibc_and_transitive_dependencies(self):
        paths, loader = module.dependencies("""
linux-vdso.so.1 (0x00001)
libndpi.so.4 => /usr/lib/libndpi.so.4 (0x00002)
libtrace.so.7 => /usr/lib/libtrace.so.7 (0x00003)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00004)
 /lib64/ld-linux-x86-64.so.2 (0x00005)
""")
        self.assertEqual(loader, "/lib64/ld-linux-x86-64.so.2")
        self.assertEqual(len(paths), 4)

    def test_musl(self):
        _, loader = module.dependencies(" /lib/ld-musl-x86_64.so.1 (0x1)\nlibndpi.so.4 => /usr/lib/libndpi.so.4 (0x2)")
        self.assertEqual(loader, "/lib/ld-musl-x86_64.so.1")

    def test_missing_dependency_fails(self):
        with self.assertRaises(ValueError):
            module.dependencies("libndpi.so.4 => not found\n /lib64/ld-linux-x86-64.so.2 (0x1)")

    def test_missing_loader_fails(self):
        with self.assertRaises(ValueError):
            module.dependencies("libndpi.so.4 => /usr/lib/libndpi.so.4 (0x2)")


if __name__ == "__main__":
    unittest.main()
