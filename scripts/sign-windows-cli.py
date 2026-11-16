#!/usr/bin/env python3
"""GoReleaser production Windows signing hook; snapshots remain unsigned."""
import os
from pathlib import Path
import re
import shlex
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'scripts/windows-signing'))
from windows_sign import install, sign


def main():
    if len(sys.argv) != 3 or sys.argv[2] not in ('true', 'false'):
        raise ValueError('usage: sign-windows-cli.py executable IsSnapshot')
    if sys.argv[2] == 'true':
        print('Snapshot Windows binary remains unsigned')
        return
    if not os.environ.get('SSL_COM_PASSWORD') or not os.environ.get('SSL_COM_TOTP_SECRET'):
        secret_file = Path(os.environ.get('SSL_COM_ENV_FILE', str(ROOT.parent / 'products/.env')))
        if secret_file.is_file():
            for line in secret_file.read_text().splitlines():
                match = re.match(r'(?:export\s+)?(SSL_COM_PASSWORD|SSL_COM_TOTP_SECRET)\s*=\s*(.*)', line)
                if match:
                    value = match.group(2).strip()
                    os.environ.setdefault(match.group(1), shlex.split(value)[0] if value[:1] in ('"', "'") else value)
    if not os.environ.get('JAVA'):
        home = os.environ.get('JAVA_HOME_21_X64') or os.environ.get('JAVA_HOME')
        if home:
            os.environ['JAVA'] = str(Path(home) / ('bin/java.exe' if os.name == 'nt' else 'bin/java'))
        elif Path('/opt/homebrew/opt/openjdk@21/bin/java').is_file():
            os.environ['JAVA'] = '/opt/homebrew/opt/openjdk@21/bin/java'
    with tempfile.TemporaryDirectory(prefix='netcap-signing-') as temporary:
        if not os.environ.get('CODE_SIGN_TOOL_PATH'):
            tool = Path(temporary) / 'tool'
            install(tool)
            os.environ['CODE_SIGN_TOOL_PATH'] = str(tool)
        sign([Path(sys.argv[1])])


if __name__ == '__main__':
    main()
