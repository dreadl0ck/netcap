#!/bin/sh
# Disposable qualification container only; all interfaces/routes live in named netns.
set -eu
test -f /.dockerenv
servers=''
daemon=''
cleanup() {
  if [ -n "$daemon" ]; then kill "$daemon" 2>/dev/null || true; wait "$daemon" || true; fi
  for pid in $servers; do kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; done
  for ns in cli-client cli-router cli-origin; do ip netns del "$ns"; done
}
trap cleanup EXIT
for ns in cli-client cli-router cli-origin; do ip netns add "$ns"; ip -n "$ns" link set lo up; done
ip -n cli-client link add c0 type veth peer name g0 netns cli-router
ip -n cli-origin link add o0 type veth peer name g1 netns cli-router
ip -n cli-client addr add 10.80.0.2/24 dev c0
ip -n cli-router addr add 10.80.0.1/24 dev g0
ip -n cli-router addr add 10.81.0.1/24 dev g1
ip -n cli-origin addr add 10.81.0.2/24 dev o0
ip -n cli-client link set c0 up; ip -n cli-router link set g0 up
ip -n cli-router link set g1 up; ip -n cli-origin link set o0 up
ip -n cli-client route add default via 10.80.0.1
ip -n cli-origin route add default via 10.81.0.1
ip netns exec cli-router sysctl -qw net.ipv4.ip_forward=1
for port in 8080 8081; do
  NFW_HELPER=server NFW_ADDRESS="10.81.0.2:$port" ip netns exec cli-origin \
    /networkfirewall.test -test.run '^TestLabHelper$' >/tmp/server-$port.log 2>&1 &
  servers="$servers $!"
done
probe() {
  NFW_HELPER=client NFW_ADDRESS="10.81.0.2:$1" ip netns exec cli-client \
    /networkfirewall.test -test.run '^TestLabHelper$'
}
sleep 0.2
probe 8080; probe 8081
/netcap-firewall network --namespace cli-router --interface g0 --protected-cidr 10.81.0.2/32 \
  --hook forward --failure-verdict deny --policy /network-policy.yaml >/tmp/network-cli.log 2>&1 &
daemon=$!
ready=false
for i in $(seq 1 50); do
  if ip netns exec cli-router nft list table inet netcap_networkfirewall >/dev/null 2>&1; then ready=true; break; fi
  sleep 0.1
done
if [ "$ready" != true ]; then cat /tmp/network-cli.log; exit 1; fi
probe 8080
if probe 8081 >/tmp/network-denial.log 2>&1; then cat /tmp/network-denial.log; exit 1; fi
grep -q 'i/o timeout' /tmp/network-denial.log
kill "$daemon"; wait "$daemon"; daemon=''
probe 8081
echo 'PASS: standalone network CLI allows 8080, drops 8081 and restores traffic after shutdown'
