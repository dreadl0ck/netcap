import hashlib
import http.client
import io
import ssl
import unittest
import urllib.error
from unittest.mock import patch

import firewall_download as download

URL = 'https://example.test/pinned-archive'


class Downloads(unittest.TestCase):
    def test_each_transient_http_status_retries_and_closes_failed_response(self):
        for code in download.TRANSIENT_HTTP:
            with self.subTest(code=code):
                body = io.BytesIO(b'upstream failure')
                error = urllib.error.HTTPError(URL, code, 'temporary', {}, body)
                success = io.BytesIO(b'archive')
                with patch.object(download.urllib.request, 'urlopen', side_effect=[error, success]) as fetch, \
                        patch.object(download.time, 'sleep') as sleep, patch('sys.stderr', new_callable=io.StringIO) as diagnostics:
                    self.assertEqual(download.verified_read(URL, hashlib.sha256(b'archive').hexdigest()), b'archive')
                self.assertEqual(fetch.call_count, 2)
                self.assertEqual(fetch.call_args.args, (URL,))
                sleep.assert_called_once_with(1)
                self.assertTrue(body.closed)
                self.assertTrue(success.closed)
                self.assertIn('attempt 1/3', diagnostics.getvalue())

    def test_exhaustion_raises_after_three_attempts(self):
        errors = [urllib.error.HTTPError(URL, 504, 'timeout', {}, io.BytesIO()) for _ in range(3)]
        with patch.object(download.urllib.request, 'urlopen', side_effect=errors) as fetch, \
                patch.object(download.time, 'sleep') as sleep:
            with self.assertRaises(urllib.error.HTTPError):
                download.read(URL, max_bytes=100)
        self.assertEqual(fetch.call_count, 3)
        self.assertEqual([c.args[0] for c in sleep.call_args_list], [1, 2])
        self.assertTrue(all(error.fp.closed for error in errors))

    def test_transport_timeout_reset_and_incomplete_read_retry(self):
        for error in (TimeoutError(), ConnectionResetError(), http.client.IncompleteRead(b'partial'),
                      urllib.error.URLError(TimeoutError()), urllib.error.URLError(ConnectionResetError())):
            with self.subTest(error=type(error)), patch.object(download.urllib.request, 'urlopen', side_effect=[error, io.BytesIO(b'ok')]), \
                    patch.object(download.time, 'sleep'):
                self.assertEqual(download.read(URL, max_bytes=100), b'ok')

    def test_read_failure_closes_response_and_discards_partial_bytes(self):
        class Partial(io.BytesIO):
            def read1(self, size):
                raise http.client.IncompleteRead(b'partial', 20)

        partial = Partial()
        with patch.object(download.urllib.request, 'urlopen', side_effect=[partial, io.BytesIO(b'complete')]), \
                patch.object(download.time, 'sleep'):
            self.assertEqual(download.read(URL, max_bytes=100), b'complete')
        self.assertTrue(partial.closed)

    def test_permanent_http_certificate_and_other_errors_do_not_retry(self):
        for error in (urllib.error.HTTPError(URL, 404, 'absent', {}, io.BytesIO()),
                      ssl.SSLCertVerificationError('certificate failure'),
                      urllib.error.URLError(ssl.SSLCertVerificationError('certificate failure')),
                      urllib.error.HTTPError(URL, 403, 'forbidden', {}, io.BytesIO()),
                      urllib.error.URLError('unsupported failure')):
            with self.subTest(error=type(error)), patch.object(download.urllib.request, 'urlopen', side_effect=error) as fetch, \
                    patch.object(download.time, 'sleep') as sleep:
                with self.assertRaises(type(error)):
                    download.read(URL, max_bytes=100)
                fetch.assert_called_once()
                sleep.assert_not_called()

    def test_checksum_mismatch_even_after_retry_is_final(self):
        error = urllib.error.HTTPError(URL, 504, 'timeout', {}, io.BytesIO())
        with patch.object(download.urllib.request, 'urlopen', side_effect=[error, io.BytesIO(b'bad')]) as fetch, \
                patch.object(download.time, 'sleep') as sleep:
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                download.verified_read(URL, hashlib.sha256(b'good').hexdigest())
        self.assertEqual(fetch.call_count, 2)
        sleep.assert_called_once()
        with patch.object(download.urllib.request, 'urlopen', return_value=io.BytesIO(b'bad')) as fetch:
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                download.verified_read(URL, '0' * 64)
            fetch.assert_called_once()

    def test_byte_limits_with_and_without_content_length(self):
        for length in (None, '5'):
            response = io.BytesIO(b'12345')
            response.headers = {} if length is None else {'Content-Length': length}
            with self.subTest(length=length), patch.object(download.urllib.request, 'urlopen', return_value=response) as fetch:
                with self.assertRaisesRegex(ValueError, 'byte limit'):
                    download.read(URL, max_bytes=4)
                fetch.assert_called_once()
                self.assertTrue(response.closed)
        self.assertEqual(download.ARCHIVE_LIMIT, 256 * 1024 * 1024)
        self.assertEqual(download.CHECKSUM_LIMIT, 4 * 1024 * 1024)

    def test_elapsed_timeout_and_content_length_truncation_are_bounded(self):
        truncated = io.BytesIO(b'short')
        truncated.headers = {'Content-Length': '10'}
        with patch.object(download.urllib.request, 'urlopen', side_effect=[truncated, io.BytesIO(b'ok')]), \
                patch.object(download.time, 'sleep'):
            self.assertEqual(download.read(URL, max_bytes=100), b'ok')
        with patch.object(download.urllib.request, 'urlopen', side_effect=lambda *a, **k: io.BytesIO(b'data')) as fetch, \
                patch.object(download.time, 'monotonic', side_effect=[0, 61, 62, 123, 124, 185]), \
                patch.object(download.time, 'sleep'):
            with self.assertRaises(TimeoutError):
                download.read(URL, max_bytes=100)
        self.assertEqual(fetch.call_count, 3)

    def test_invalid_checksum_or_headers_fail_without_retry(self):
        with patch.object(download.urllib.request, 'urlopen') as fetch:
            with self.assertRaisesRegex(ValueError, 'expected SHA256'):
                download.verified_read(URL, 'malformed')
            fetch.assert_not_called()
        response = io.BytesIO(b'data')
        response.headers = {'Content-Length': 'invalid'}
        with patch.object(download.urllib.request, 'urlopen', return_value=response) as fetch:
            with self.assertRaises(ValueError):
                download.read(URL, max_bytes=100)
            fetch.assert_called_once()
        self.assertTrue(response.closed)


if __name__ == '__main__':
    unittest.main()
