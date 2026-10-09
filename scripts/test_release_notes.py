from pathlib import Path
import runpy
import unittest

validate = runpy.run_path(str(Path(__file__).with_name("check-release-notes.py")))["validate"]


class ReleaseNotesTests(unittest.TestCase):
    def test_accepts_body_sections(self):
        validate("## What's new\n\nFeature summary.\n### Details\nMore detail.")

    def test_rejects_empty_and_duplicate_titles(self):
        for text in ("", "  \n", "# Netcap v1.0\n", "  # Netcap\n", "Netcap v1.0\n=====\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                validate(text)


if __name__ == "__main__":
    unittest.main()
