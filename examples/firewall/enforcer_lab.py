#!/usr/bin/env python3
"""Run the existing real-kernel Go tests in a disposable container, without host mounts."""
import argparse
import json
import platform
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default='netcap-enforcer:qualification')
    parser.add_argument('--skip-build', action='store_true')
    args = parser.parse_args()
    if not args.skip_build:
        subprocess.run(['docker', 'build', '-f', 'docker/enforcer/Dockerfile',
                        '--target', 'qualification', '-t', args.image, '.'], check=True)
        subprocess.run(['docker', 'build', '-f', 'docker/enforcer/Dockerfile',
                        '--target', 'release', '-t', 'netcap-enforcer:0.1.0-local', '.'], check=True)
    command = ['docker', 'run', '--rm', '--network=none', '--cap-drop=ALL',
               '--cap-add=NET_ADMIN', '--cap-add=SYS_ADMIN',
               '--security-opt=seccomp=unconfined', '--security-opt=apparmor=unconfined',
               '--env', 'ENFORCER_NETNS_TEST=1', '--entrypoint', '/bin/sh', args.image,
               '-ec', 'mount -t proc proc /proc; nft -j list ruleset > /tmp/before; '
               '/enforcer.test -test.v -test.timeout=120s > /tmp/results 2>&1 || '
               '{ cat /tmp/results; exit 1; }; '
               'cat /tmp/results; ! grep -q -- "--- SKIP" /tmp/results; '
               'grep -q -- "--- PASS: TestNFTNetworkNamespace" /tmp/results; '
               'grep -q -- "--- PASS: TestNFTSingletonProcess" /tmp/results; '
               '/bin/sh /enforcer_package.sh; '
               'nft -j list ruleset > /tmp/after; cmp /tmp/before /tmp/after']
    subprocess.run(command, check=True, timeout=180)
    arch = subprocess.check_output(['docker', 'info', '--format', '{{.Architecture}}'], text=True).strip()
    print(json.dumps({'result': 'pass', 'docker_arch': arch, 'client_arch': platform.machine(),
                      'host_mounts': False, 'privileged': False,
                      'capabilities': ['NET_ADMIN', 'SYS_ADMIN'],
                      'checks': ['existing integration suite, no skips', 'container default ruleset unchanged']}))


if __name__ == '__main__':
    main()
