#!/bin/sh
# Runs only inside the no-host-mount disposable qualification container.
set -eu
test -f /.dockerenv
export NETCAP_FIREWALL_ADMIN_TOKEN=isolated-lab-token-not-a-real-credential
export ENFORCER_LEGACY_ADMIN=true # Trusted isolated lab compatibility only.
export ENFORCER_NAMESPACE=nce_package ENFORCER_INTERFACE=lo
export ENFORCER_DESTINATION=198.51.100.0/24 ENFORCER_PORT=8080 ENFORCER_HOOK=input
ip netns add "$ENFORCER_NAMESPACE"
daemon=''
cleanup() {
  if [ -n "$daemon" ]; then kill "$daemon" 2>/dev/null || true; wait "$daemon" || true; fi
  ip netns del "$ENFORCER_NAMESPACE"
  umount /run/netns/forbidden 2>/dev/null || true
}
trap cleanup EXIT
/bin/sh /entrypoint.sh --dry-run=false >/tmp/package.log 2>&1 &
daemon=$!
ready=false
for i in $(seq 1 50); do
  if wget -qO /tmp/leases --header="Authorization: Bearer $NETCAP_FIREWALL_ADMIN_TOKEN" \
    http://127.0.0.1:9091/v1/leases; then ready=true; break; fi
  sleep 0.1
done
if [ "$ready" != true ]; then cat /tmp/package.log; exit 1; fi
if wget -qO /dev/null http://127.0.0.1:9091/v1/leases; then exit 1; fi
ip netns exec "$ENFORCER_NAMESPACE" nft list table inet netcap_firewall_lab >/dev/null
kill "$daemon"; wait "$daemon"; daemon=''
touch /run/netns/forbidden
mount --bind /proc/self/ns/net /run/netns/forbidden
if ENFORCER_NAMESPACE=forbidden /bin/sh /entrypoint.sh --dry-run=false >/tmp/refusal 2>&1; then exit 1; fi
grep -q 'refusing current or PID 1 network namespace' /tmp/refusal
echo 'PASS: packaged live CLI, bearer isolation, named table creation, default namespace bind refused'
