#!/usr/bin/env python3
"""Unattended eSigner signing; verify trust, timestamp and unchanged PE content."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile

TOOL_VERSION = '1.3.2'
TOOL_SHA256 = 'f14b1e1ef14bfa1fd00279c363aab0debbf5dcfba0e4bcdce5d22bb771de0e3a'
TOOL_URL = f'https://github.com/SSLcom/CodeSignTool/releases/download/v{TOOL_VERSION}/CodeSignTool-v{TOOL_VERSION}.zip'
CREDENTIAL = 'bf227013-1dd4-4572-b0a1-7fea9e403751'
SERIAL = '30A8A2C3F3F860458F40426572FE210A'
ROOT = Path(__file__).resolve().parent


def sha(path):
    with Path(path).open('rb') as stream:
        digest = hashlib.sha256()
        for block in iter(lambda: stream.read(1048576), b''):
            digest.update(block)
    return digest.hexdigest()


def pe_content(path):
    data = bytearray(Path(path).read_bytes())
    offset = struct.unpack_from('<I', data, 0x3c)[0]
    if data[offset:offset + 4] != b'PE\0\0':
        raise ValueError('not a PE image: ' + str(path))
    optional = offset + 24
    magic = struct.unpack_from('<H', data, optional)[0]
    if magic not in (0x10b, 0x20b):
        raise ValueError('unsupported PE optional header')
    security = optional + (112 if magic == 0x20b else 96) + 32
    start, size = struct.unpack_from('<II', data, security)
    if size:
        if start < security + 8 or start + size != len(data):
            raise ValueError('invalid PE certificate table')
        del data[start:]
    data[optional + 64:optional + 68] = b'\0' * 4
    data[security:security + 8] = b'\0' * 8
    return bytes(data)


def verify_transformation(original, signed):
    before, after = pe_content(original), pe_content(signed)
    if after[:len(before)] != before or not 0 <= len(after) - len(before) <= 7 or any(after[len(before):]):
        raise ValueError('signing changed executable content: ' + Path(original).name)


def install(destination, archive=None):
    destination = Path(destination)
    if destination.exists():
        raise ValueError('tool destination already exists')
    with tempfile.TemporaryDirectory() as scratch:
        source = Path(archive) if archive else Path(scratch) / 'tool.zip'
        if not archive:
            with urllib.request.urlopen(TOOL_URL, timeout=60) as response, source.open('wb') as output:
                shutil.copyfileobj(response, output)
        if sha(source) != TOOL_SHA256:
            raise ValueError('CodeSignTool checksum mismatch')
        destination.mkdir(parents=True)
        with zipfile.ZipFile(source) as bundle:
            for entry in bundle.infolist():
                path = Path(entry.filename)
                if path.is_absolute() or '..' in path.parts or '\\' in entry.filename:
                    raise ValueError('unsafe tool archive')
            bundle.extractall(destination)
    (destination / 'quiet-log4j.xml').write_text('<Configuration status="OFF"><Loggers><Root level="off"/></Loggers></Configuration>')


def verify(path):
    path = Path(path).resolve()
    if sys.platform == 'win32':
        subprocess.run(['pwsh.exe', '-NoProfile', '-NonInteractive', '-File',
                        str(ROOT / 'verify-windows-signature.ps1'), '-Path', str(path), '-Serial', SERIAL],
                       check=True, timeout=120)
    else:
        result = subprocess.run(['osslsigncode', 'verify', '-in', str(path)], capture_output=True, text=True, timeout=120)
        output = result.stdout + result.stderr
        signer = re.search(r"Signer's certificate:.*?Serial\s*:\s*([A-F0-9]+)", output, re.DOTALL)
        if result.returncode or not signer or signer.group(1) != SERIAL or 'Timestamp Server Signature verification: ok' not in output:
            raise ValueError('untrusted certificate/signature/timestamp: ' + path.name)
    print('Verified Authenticode and timestamp: ' + path.name, flush=True)


def java_arg(value):
    if '\n' in value or '\r' in value:
        raise ValueError('newline in Java argument')
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def sign(paths):
    paths = [Path(p).absolute() for p in paths]
    uninstaller = os.environ.get('WINDOWS_UNINSTALLER_COPY')
    if not paths or len({p.name.lower() for p in paths}) != len(paths) or (uninstaller and len(paths) != 1):
        raise ValueError('invalid signing input set')
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ValueError('signing requires regular files')
    names = ['uninstall.exe'] if uninstaller else [p.name for p in paths]
    password, seed = os.environ.get('SSL_COM_PASSWORD', ''), os.environ.get('SSL_COM_TOTP_SECRET', '')
    if not password or not seed:
        raise ValueError('SSL_COM_PASSWORD and SSL_COM_TOTP_SECRET are required')
    tool = Path(os.environ['CODE_SIGN_TOOL_PATH']).resolve()
    env = {k: v for k, v in os.environ.items() if k not in
           ('SSL_COM_PASSWORD', 'SSL_COM_TOTP_SECRET', 'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS')}
    with tempfile.TemporaryDirectory(prefix='estate-sign-') as temporary:
        work = Path(temporary)
        inputs, outputs = work / 'input', work / 'output'
        inputs.mkdir()
        outputs.mkdir()
        for index, (path, name) in enumerate(zip(paths, names)):
            shutil.copyfile(path, inputs / name)
            arguments = [f'-Dlog4j.configurationFile={tool / "quiet-log4j.xml"}', '-jar',
                         str(tool / f'jar/code_sign_tool-{TOOL_VERSION}.jar'), 'sign',
                         '-username=amstech1337', '-password=' + password, '-credential_id=' + CREDENTIAL,
                         '-totp_secret=' + seed, '-input_file_path=' + str(inputs / name),
                         '-output_dir_path=' + str(outputs)]
            argfile = work / f'java-{index}.args'
            fd = os.open(argfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                handle.write('\n'.join(java_arg(a) for a in arguments))
            remaining = 30 - time.time() % 30
            if remaining < 5:
                time.sleep(remaining + 1)
            result = subprocess.run([os.environ.get('JAVA', 'java'), '@' + str(argfile)], cwd=tool,
                                    env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=240)
            argfile.unlink()
            if result.returncode or not (outputs / name).is_file():
                reason = ' (invalid OTP)' if 'invalid otp' in (result.stdout + result.stderr).lower() else ''
                raise ValueError('eSigner did not produce a signed output' + reason)
            verify(outputs / name)
            verify_transformation(path, outputs / name)
        for path, name in zip(paths, names):
            shutil.copyfile(outputs / name, path)
        if uninstaller:
            shutil.copyfile(paths[0], uninstaller)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    setup = sub.add_parser('install')
    setup.add_argument('destination', type=Path)
    setup.add_argument('--archive', type=Path)
    for name in ('sign', 'verify'):
        sub.add_parser(name).add_argument('paths', nargs='+', type=Path)
    args = parser.parse_args()
    try:
        if args.command == 'install':
            install(args.destination, args.archive)
        elif args.command == 'sign':
            sign(args.paths)
        else:
            for path in args.paths:
                verify(path)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
