import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

import runner


class OwnershipTests(unittest.TestCase):
    def test_provenance_records_hashes_without_source_bodies_or_git_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            source = root / 'source.go'
            source.write_text('sensitive-body-must-not-appear')
            binary = root / 'runner'
            binary.write_bytes(b'fixture')
            outputs = [b'source.go\0', 'a' * 40 + '\n', 'b' * 40 + '\n', b'', 'build metadata']
            with patch.object(runner, 'ROOT', root), patch.object(runner.subprocess, 'check_output', side_effect=outputs):
                receipt = runner.provenance(binary)
            self.assertNotIn('sensitive-body', json.dumps(receipt))
            self.assertEqual(set(receipt['source_sha256']), {'source.go'})
            self.assertTrue(receipt['clean'])

    def test_wait_observes_completion_without_relaunch(self):
        states = [dict(state='running', supervisor_owned_live=True),
                  dict(state='pass', supervisor_owned_live=False)]
        with patch.object(runner, 'inspect', side_effect=states), \
                patch.object(runner.time, 'sleep'), \
                patch.object(runner.subprocess, 'Popen') as launch:
            self.assertEqual(runner.wait(pathlib.Path('/unused'), 10)['state'], 'pass')
        launch.assert_not_called()

    def test_wait_refuses_an_orphaned_checkpoint(self):
        with patch.object(runner, 'inspect', return_value=dict(state='running', supervisor_owned_live=False)):
            with self.assertRaises(ValueError):
                runner.wait(pathlib.Path('/unused'), 10)

    def test_birth_command_and_token_must_all_match(self):
        token = 'a' * 32
        identity = 'Sat Nov 7 22:36:10 2026 python runner.py _worker --token ' + token
        manifest = dict(owner=runner.OWNER, token=token, supervisor_pid=123,
                        supervisor_identity=identity)
        with patch.object(runner, 'identity', return_value=identity):
            self.assertTrue(runner.owned(manifest))
            for changed in (dict(owner='unowned'), dict(token='b' * 32),
                            dict(token=None), dict(supervisor_pid=-1),
                            dict(supervisor_identity='different birth time ' + identity)):
                self.assertFalse(runner.owned(dict(manifest, **changed)))
        with patch.object(runner, 'identity', return_value=None):
            self.assertFalse(runner.owned(manifest))

    def test_resume_reads_checkpoint_without_restarting_or_signalling(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = pathlib.Path(temp)
            manifest = dict(owner=runner.OWNER, state='fail', token='a' * 32,
                            supervisor_pid=123, supervisor_identity='old', elapsed_seconds=17)
            runner.write(directory / 'manifest.json', manifest)
            with patch.object(runner, 'identity', return_value=None), \
                    patch.object(runner.subprocess, 'Popen') as launch, \
                    patch.object(runner.os, 'kill') as kill:
                result = runner.inspect(directory)
            self.assertFalse(result['supervisor_owned_live'])
            self.assertEqual(result['elapsed_seconds'], 17)
            launch.assert_not_called()
            kill.assert_not_called()
            self.assertEqual(json.loads((directory / 'manifest.json').read_text()), manifest)

    def test_unknown_manifest_cannot_be_adopted(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = pathlib.Path(temp)
            runner.write(directory / 'manifest.json', dict(owner='somebody-else'))
            with self.assertRaises(ValueError):
                runner.inspect(directory)

    def test_corrupt_progress_cannot_hide_supervisor_ownership(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = pathlib.Path(temp)
            token = 'a' * 32
            identity = 'birth python --token ' + token
            runner.write(directory / 'manifest.json', dict(owner=runner.OWNER, token=token,
                         supervisor_pid=123, supervisor_identity=identity))
            (directory / 'http').mkdir()
            (directory / 'http' / 'progress.json').write_text('{')
            with patch.object(runner, 'identity', return_value=identity):
                result = runner.inspect(directory)
            self.assertTrue(result['supervisor_owned_live'])
            self.assertIn('report_error', result)


if __name__ == '__main__':
    unittest.main()
