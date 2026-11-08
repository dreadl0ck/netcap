import hashlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from unittest.mock import Mock, patch

import firewall_download as download

EXAMPLES = Path(__file__).resolve().parents[1] / 'examples/firewall'
spec = importlib.util.spec_from_file_location('cni_download_test_subject', EXAMPLES / 'cni_qualification.py')
cni = importlib.util.module_from_spec(spec)
with patch.object(sys, 'path', [str(EXAMPLES), *sys.path]):
    spec.loader.exec_module(cni)


class MetricsDownload(unittest.TestCase):
    def test_official_pin(self):
        self.assertEqual(cni.METRICS_VERSION, '3.12.2')
        self.assertEqual(cni.METRICS_SHA256, 'e904ffa2fe33c429e12cac8aa013ba38f42d944e315d060e94230a53b98985cf')
        self.assertIn('/metrics-server-helm-chart-3.12.2/metrics-server-3.12.2.tgz', cni.METRICS_URL)

    def test_verified_prefetch_then_single_local_helm_install(self):
        payload = b'synthetic chart'
        error = urllib.error.HTTPError(cni.METRICS_URL, 504, 'timeout', {}, io.BytesIO())
        with tempfile.TemporaryDirectory() as tmp, patch.object(cni, 'METRICS_SHA256', hashlib.sha256(payload).hexdigest()), \
                patch.object(download.urllib.request, 'urlopen', side_effect=[error, io.BytesIO(payload)]) as fetch, \
                patch.object(download.time, 'sleep'):
            chart = cni.metrics_chart(Path(tmp))
            self.assertEqual(chart.read_bytes(), payload)
            self.assertEqual(fetch.call_count, 2)
            run = Mock(side_effect=subprocess.CalledProcessError(1, 'helm'))
            with self.assertRaises(subprocess.CalledProcessError):
                cni.install_metrics(run, chart, 'owned-lab')
            run.assert_called_once()
            command = run.call_args.args
            self.assertEqual(command[:4], ('helm', 'install', 'metrics-server', str(chart)))
            self.assertNotIn('--repo', command)
            self.assertNotIn('--version', command)

    def test_hash_failure_never_writes_or_installs_chart(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(download.urllib.request, 'urlopen', return_value=io.BytesIO(b'bad')) as fetch:
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                cni.metrics_chart(Path(tmp))
            self.assertEqual(list(Path(tmp).iterdir()), [])
            fetch.assert_called_once()

    def test_exhaustion_never_creates_cluster_or_success_report(self):
        errors = [urllib.error.HTTPError(cni.METRICS_URL, 504, 'timeout', {}, io.BytesIO()) for _ in range(3)]
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(sys, 'argv', ['cni_qualification.py', '--output', str(Path(tmp) / 'result.json')]), \
                patch.object(download.urllib.request, 'urlopen', side_effect=errors) as fetch, \
                patch.object(download.time, 'sleep'), patch.object(cni.subprocess, 'run') as run:
            with self.assertRaises(urllib.error.HTTPError):
                cni.main()
            self.assertEqual(fetch.call_count, 3)
            run.assert_not_called()
            self.assertFalse((Path(tmp) / 'result.json').exists())


if __name__ == '__main__':
    unittest.main()
