#!/usr/bin/env python3
"""Compile and qualify appliance lifecycle in one disposable, networkless Linux container."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    root = Path(__file__).resolve().parents[2]
    arch = subprocess.check_output(
        ['docker', 'info', '--format', '{{.Architecture}}'], text=True).strip()
    arch = {'aarch64': 'arm64', 'x86_64': 'amd64'}.get(arch, arch)
    if arch not in ('arm64', 'amd64'):
        raise SystemExit(f'unsupported Docker architecture: {arch}')
    env = dict(os.environ, GOOS='linux', GOARCH=arch, CGO_ENABLED='0')
    with tempfile.TemporaryDirectory(prefix='netcap-appliance-') as work:
        work = Path(work)
        for package in ('appliance', 'networkfirewall', 'transparentfirewall'):
            subprocess.run(['go', 'test', '-c', '-o', str(work / f'{package}.test'),
                            f'./internal/{package}'], cwd=root, env=env, check=True)
        subprocess.run(['go', 'build', '-o', str(work / 'firewall'),
                        './cmd/netcap-firewall'], cwd=root, env=env, check=True)
        shutil.copyfile(root / 'internal/appliance/Dockerfile.lab', work / 'Dockerfile')
        shutil.copyfile(root / 'examples/firewall/appliance-lab.json', work / 'appliance-lab.json')
        image = 'netcap-appliance:qualification'
        subprocess.run(['docker', 'build', '-t', image, str(work)], check=True)
        script = '''mount -t proc proc /proc
/appliance.test -test.v -test.run 'TestAppliance.*Lab|TestManifest|TestPlan' -test.timeout=120s
/networkfirewall.test -test.v -test.run '^Test(Routed|FenceFD)Lab$' -test.timeout=180s
/transparentfirewall.test -test.v -test.run '^TestTransparentLab$' -test.timeout=180s
/firewall appliance plan --manifest /lab/examples/firewall/appliance-lab.json > /tmp/plan
/firewall appliance apply --dry-run --manifest /lab/examples/firewall/appliance-lab.json > /tmp/dry
cmp /tmp/plan /tmp/dry
/firewall appliance apply --manifest /lab/examples/firewall/appliance-lab.json > /tmp/applied
/firewall appliance recover --manifest /lab/examples/firewall/appliance-lab.json > /tmp/recovered
/firewall appliance status --manifest /lab/examples/firewall/appliance-lab.json > /tmp/status
/firewall appliance remove --manifest /lab/examples/firewall/appliance-lab.json > /tmp/removed
'''
        result = subprocess.run(['docker', 'run', '--rm', '--network=none', '--cap-drop=ALL',
                                 '--cap-add=NET_ADMIN', '--cap-add=SYS_ADMIN', '--cap-add=NET_RAW',
                                 '--security-opt=seccomp=unconfined', '--security-opt=apparmor=unconfined',
                                 image, script], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=540)
        print(result.stdout, end='')
        if result.returncode or '--- SKIP' in result.stdout:
            raise SystemExit(result.returncode or 1)
        for test in ('TestApplianceLinuxLab', 'TestApplianceCrashLab', 'TestApplianceGatewayLab', 'TestApplianceRemovalCrashLab', 'TestRoutedLab', 'TestFenceFDLab', 'TestTransparentLab'):
            if f'--- PASS: {test} ' not in result.stdout:
                raise SystemExit(f'missing qualification: {test}')
        print('PASS: appliance lifecycle, crash recovery, packet handoff, CLI JSON, routed and transparent regressions')


if __name__ == '__main__':
    main()
