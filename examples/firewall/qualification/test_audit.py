import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

import audit
from runner import OWNER, digest


class ReceiptTests(unittest.TestCase):
    def test_modified_completed_receipt_fails_before_any_process_is_started(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            run = root / 'run'
            (run / 'http').mkdir(parents=True)
            for name in ('progress', 'falsepositives'):
                (run / 'http' / (name + '.json')).write_text('{}')
            binary = root / 'binary'
            binary.write_bytes(b'owned test binary; never executed')
            (run / 'manifest.json').write_text(json.dumps(dict(owner=OWNER, state='pass',
                binary=str(binary), binary_sha256=digest(binary),
                receipt_sha256={'http/progress.json': '0' * 64})))
            for name in ('ftw', 'protocols', 'pilot'):
                directory = root / name
                directory.mkdir()
                (directory / (name + '.json')).write_text('{}')
            output = root / 'output'
            output.mkdir()
            with patch.object(audit.subprocess, 'run') as launch:
                with self.assertRaisesRegex(ValueError, 'completed receipt changed'):
                    audit.audit(run, root / 'ftw', root / 'protocols', root / 'pilot', output)
            launch.assert_not_called()


if __name__ == '__main__':
    unittest.main()
