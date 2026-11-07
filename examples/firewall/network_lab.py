#!/usr/bin/env python3
"""Qualify routed NFQUEUE traffic in disposable named namespaces without host mounts."""
import argparse
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default='netcap-enforcer:qualification')
    args = parser.parse_args()
    subprocess.run(['docker', 'run', '--rm', '--network=none', '--cap-drop=ALL',
                    '--cap-add=NET_ADMIN', '--cap-add=SYS_ADMIN', '--cap-add=NET_RAW',
                    '--security-opt=seccomp=unconfined', '--security-opt=apparmor=unconfined',
                    '--env', 'NETCAP_NETWORKFIREWALL_LAB=1', '--entrypoint', '/bin/sh', args.image,
                    '-ec', 'mount -t proc proc /proc; nft -j list ruleset >/tmp/before; '
                    '/networkfirewall.test -test.v -test.run "^TestRoutedLab$" -test.timeout=180s >/tmp/results 2>&1 || '
                    '{ cat /tmp/results; exit 1; }; cat /tmp/results; '
                    '! grep -q -- "--- SKIP" /tmp/results; '
                    'grep -q -- "--- PASS: TestRoutedLab" /tmp/results; '
                    '/bin/sh /network_package.sh; '
                    'nft -j list ruleset >/tmp/after; cmp /tmp/before /tmp/after'],
                   check=True, timeout=210)
    print('PASS: routed packet lab; no test skips; default namespace ruleset unchanged')


if __name__ == '__main__':
    main()
