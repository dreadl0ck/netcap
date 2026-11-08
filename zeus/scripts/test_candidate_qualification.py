import base64
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MAC = load('macos-candidate')
LINUX = load('native-candidate')
WINDOWS = load('qualify-windows-npcap')


class MacCandidateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'lib').mkdir()
        (self.root / 'net').write_bytes(b'executable')
        (self.root / 'lib/yara.dylib').write_bytes(b'library')
        self.minimum = '15.0'
        self.library_minimum = '11.0'
        self.arch = 'arm64'
        self.dependency = '@executable_path/lib/yara.dylib'
        self.team = 'TESTTEAM'
        self.signature = 'TeamIdentifier=TESTTEAM\nTimestamp=Nov 8 2026\nflags=0x10000(runtime)\n'
        self.inventory = dict(minimumOS='15.0', files=[dict(file='lib/yara.dylib', sha256=MAC.sha(self.root / 'lib/yara.dylib'))])
        (self.root / 'native-runtime-inventory.json').write_text(json.dumps(self.inventory))

    def tool(self, command, **kwargs):
        name = str(command[0])
        path = Path(command[-1])
        if name == 'lipo':
            return self.arch + '\n'
        if name == 'vtool':
            return 'minos ' + (self.minimum if path.name == 'net' else self.library_minimum) + '\n'
        if name == 'otool':
            return str(path) + ':\n\t' + (self.dependency if path.name == 'net' else '@loader_path/yara.dylib') + ' (compatibility version 1.0)\n'
        if '--verify' in command:
            return ''
        return self.signature

    def inspect(self):
        with patch.object(MAC, 'run', side_effect=self.tool):
            return MAC.inspect(self.root, '15.0', 'arm64', self.team)

    def test_signed_minimum15_with_older_library_passes(self):
        self.assertEqual(len(self.inspect()), 2)

    def test_dependency_minimum26_rejects_advertised15(self):
        self.library_minimum = '26.0'
        with self.assertRaisesRegex(ValueError, 'minimum OS'):
            self.inspect()

    def test_wrong_binary_target_or_architecture_rejects(self):
        self.minimum = '26.0'
        with self.assertRaises(ValueError):
            self.inspect()
        self.minimum, self.arch = '15.0', 'x86_64'
        with self.assertRaisesRegex(ValueError, 'architecture'):
            self.inspect()

    def test_unrelocated_missing_and_escaping_libraries_reject(self):
        for dependency in ('/opt/homebrew/lib/yara.dylib', '@rpath/yara.dylib',
                           '@executable_path/lib/missing.dylib', '@executable_path/lib/../../outside'):
            self.dependency = dependency
            with self.subTest(dependency=dependency), self.assertRaises(ValueError):
                self.inspect()

    def test_changed_inventory_or_symlink_rejects(self):
        (self.root / 'lib/yara.dylib').write_bytes(b'changed after inventory')
        with self.assertRaisesRegex(ValueError, 'inventory'):
            self.inspect()
        (self.root / 'lib/yara.dylib').unlink()
        (self.root / 'lib/yara.dylib').symlink_to(self.root / 'net')
        with self.assertRaisesRegex(ValueError, 'regular'):
            self.inspect()

    def test_missing_inventory_rejects(self):
        (self.root / 'native-runtime-inventory.json').unlink()
        with self.assertRaisesRegex(ValueError, 'inventory is required'):
            self.inspect()

    def test_wrong_team_missing_timestamp_or_hardened_runtime_rejects(self):
        for signature in ('TeamIdentifier=OTHER\nTimestamp=now\nruntime\n', 'TeamIdentifier=TESTTEAM\nruntime\n',
                          'TeamIdentifier=TESTTEAM\nTimestamp=now\n'):
            self.signature = signature
            with self.subTest(signature=signature), self.assertRaises(ValueError):
                self.inspect()

    def test_notary_password_is_stdin_only_and_prompt_is_not_retained(self):
        result = subprocess.CompletedProcess([], 0, 'Password prompt\n{"status":"Accepted","id":"test"}', '')
        with patch.dict(os.environ, AC_USERNAME='user@example.test', AC_PASSWORD='test-secret'), \
                patch.object(MAC.subprocess, 'run', return_value=result) as execute:
            value, code = MAC.notary(['submit', 'candidate.zip', '--output-format', 'json'], 'TESTTEAM')
        self.assertEqual((value['status'], code), ('Accepted', 0))
        self.assertNotIn('test-secret', str(execute.call_args.args[0]))
        self.assertEqual(execute.call_args.kwargs['input'], 'test-secret\n')


class NativeCandidateTests(unittest.TestCase):
    def test_release_stamp_preserves_revision_and_rejects_non_semver(self):
        command = LINUX.plan('a' * 40, 'linux/amd64', ['alpine'], 'owned-builder', 'test', '0.16.0')[0]['command']
        self.assertIn('NETCAP_BUILD_VERSION=0.16.0', command)
        self.assertIn('NETCAP_BUILD_COMMIT=' + 'a' * 40, command)
        for invalid in ('v0.16.0', '0.16', '00.16.0', '0.16.0 -X injected=true'):
            with self.assertRaises(ValueError):
                LINUX.plan('a' * 40, 'linux/amd64', ['alpine'], 'owned-builder', 'test', invalid)

    def test_plan_all_four_builds_pins_revision_arch_and_never_pushes(self):
        revision = 'a' * 40
        commands = LINUX.plan(revision, 'linux/amd64', list(LINUX.VARIANTS), 'owned-builder', 'test')
        self.assertEqual(len(commands), 4)
        for item in commands:
            args = item['command']
            self.assertIn('NETCAP_BUILD_COMMIT=' + revision, args)
            self.assertIn('--load', args)
            self.assertNotIn('--push', args)
            self.assertNotIn('noyara', ' '.join(args))
            self.assertIn('@sha256:', item['builder'])
        with self.assertRaises(ValueError):
            LINUX.plan(revision, 'linux/arm64', ['alpine'], 'owned-builder', 'test')

    def test_dirty_or_wrong_source_revision_fails_before_build(self):
        with patch.object(LINUX.subprocess, 'check_output', return_value='b' * 40):
            with self.assertRaisesRegex(ValueError, 'HEAD differs'):
                LINUX.check_source('a' * 40)
        with patch.object(LINUX.subprocess, 'check_output', side_effect=['a' * 40, ' D cmd/capture/webui/frontend/dist/MODULE_PLACEHOLDER.txt\n']):
            LINUX.check_source('a' * 40)
        with patch.object(LINUX.subprocess, 'check_output', side_effect=['a' * 40, ' M go.mod']):
            with self.assertRaisesRegex(ValueError, 'clean'):
                LINUX.check_source('a' * 40)

    def test_windows_live_gate_requires_marker_and_bpf_negative_control(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'UDP.json'
            positive = dict(SrcIP='127.0.0.1', DstIP='127.0.0.1', DstPort=19999,
                            Payload=base64.b64encode(b'NETCAP_NPCAP_POSITIVE').decode())
            path.write_text(json.dumps({'Type': 37}) + '\n' + json.dumps(positive) + '\n')
            self.assertEqual(WINDOWS.live_records(directory), 1)
            path.write_text(path.read_text() + json.dumps(dict(positive, DstPort=19998)) + '\n')
            with self.assertRaises(ValueError):
                WINDOWS.live_records(directory)
            path.write_text(json.dumps({'Type': 37}) + '\n')
            with self.assertRaises(ValueError):
                WINDOWS.live_records(directory)


if __name__ == '__main__':
    unittest.main()
