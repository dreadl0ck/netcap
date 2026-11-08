"""Bounded HTTPS GETs; verification failures never enter the retry loop."""
import errno
import hashlib
import http.client
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ARCHIVE_LIMIT = 256 * 1024 * 1024
CHECKSUM_LIMIT = 4 * 1024 * 1024
ATTEMPTS = 3
TRANSIENT_HTTP = {408, 429, 500, 502, 503, 504}


def transient(error):
    if isinstance(error, urllib.error.HTTPError):
        return error.code in TRANSIENT_HTTP
    if isinstance(error, urllib.error.URLError):
        error = error.reason
    if isinstance(error, ssl.SSLError):
        return False
    return (isinstance(error, (TimeoutError, ConnectionResetError, http.client.IncompleteRead))
            or isinstance(error, OSError) and error.errno in (errno.ETIMEDOUT, errno.ECONNRESET))


def read(url, *, max_bytes, timeout=60):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('download requires an HTTPS URL without credentials')
    if type(max_bytes) is not int or not 1 <= max_bytes <= ARCHIVE_LIMIT or not 0 < timeout <= 120:
        raise ValueError('invalid download byte limit or timeout')
    label = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, '', ''))
    for attempt in range(1, ATTEMPTS + 1):
        try:
            deadline = time.monotonic() + timeout
            with urllib.request.urlopen(url, timeout=timeout) as response:
                length = getattr(response, 'headers', {}).get('Content-Length')
                length = int(length) if length is not None else None
                if length is not None and not 0 <= length <= max_bytes:
                    raise ValueError('download exceeds byte limit: ' + label)
                data = bytearray()
                # read1 returns after a single buffered/socket read, allowing elapsed checks.
                receive = getattr(response, 'read1', response.read)
                while True:
                    if time.monotonic() >= deadline:
                        raise TimeoutError('download elapsed timeout')
                    block = receive(min(64 * 1024, max_bytes + 1 - len(data)))
                    if not block:
                        break
                    data.extend(block)
                    if len(data) > max_bytes:
                        raise ValueError('download exceeds byte limit: ' + label)
                if length is not None and len(data) < length:
                    raise http.client.IncompleteRead(bytes(data), length - len(data))
                if length is not None and len(data) != length:
                    raise ValueError('download Content-Length mismatch: ' + label)
                return bytes(data)
        except (urllib.error.URLError, OSError, http.client.IncompleteRead) as error:
            if isinstance(error, urllib.error.HTTPError):
                error.close()
            retry = transient(error) and attempt < ATTEMPTS
            reason = 'HTTP ' + str(error.code) if isinstance(error, urllib.error.HTTPError) else type(error).__name__
            delay = 2 ** (attempt - 1) if retry else 0
            print(f'GET {label}: attempt {attempt}/{ATTEMPTS} failed ({reason}); '
                  + (f'retrying in {delay}s' if retry else 'not retrying'), file=sys.stderr)
            if not retry:
                raise
            time.sleep(delay)


def verified_read(url, expected_sha256, *, max_bytes=ARCHIVE_LIMIT, timeout=120):
    if not re.fullmatch('[0-9a-f]{64}', expected_sha256):
        raise ValueError('invalid expected SHA256')
    data = read(url, max_bytes=max_bytes, timeout=timeout)
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError('upstream checksum mismatch: ' + url.split('?', 1)[0])
    return data
