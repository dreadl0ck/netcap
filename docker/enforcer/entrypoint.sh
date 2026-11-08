#!/bin/sh
set -eu
mode="${ENFORCER_MODE:-leases}"
case "${1:-}" in
  --help)
    if [ "$mode" = network ]; then exec /netcap-firewall network --help; fi
    exec /netcap-firewall enforcer --help ;;
esac
: "${ENFORCER_NAMESPACE:?existing named lab namespace required}"
: "${ENFORCER_INTERFACE:?ingress interface required}"
case "$ENFORCER_NAMESPACE" in
  default|host|/|*[!a-zA-Z0-9_-]*) exit 64 ;;
esac
if [ "$mode" = network ]; then
  exec /netcap-firewall network --namespace "$ENFORCER_NAMESPACE" --interface "$ENFORCER_INTERFACE" \
    --policy /etc/netcap-network/policy.yaml --hook "${ENFORCER_HOOK:-forward}" \
    --queue "${ENFORCER_QUEUE:-100}" --max-queue-len "${ENFORCER_MAX_QUEUE_LEN:-1024}" \
    --deadline "${ENFORCER_DEADLINE:-100ms}" --failure-verdict "${ENFORCER_FAILURE_VERDICT:-deny}" "$@"
fi
[ "$mode" = leases ] || exit 64
: "${ENFORCER_DESTINATION:?destination CIDR required}"
: "${ENFORCER_PORT:?destination port required}"
if [ -n "${ENFORCER_AUTH_CONFIG:-}" ]; then
  [ "${ENFORCER_LEGACY_ADMIN:-false}" = false ] || exit 64
  set -- --auth-config "$ENFORCER_AUTH_CONFIG" "$@"
elif [ "${ENFORCER_LEGACY_ADMIN:-false}" = true ]; then
  : "${NETCAP_FIREWALL_ADMIN_TOKEN:?legacy lab bearer token required}"
  set -- --legacy-admin "$@"
else
  printf '%s\n' 'leases requires ENFORCER_AUTH_CONFIG or explicit ENFORCER_LEGACY_ADMIN=true' >&2
  exit 64
fi
exec /netcap-firewall enforcer --listen 127.0.0.1:9091 \
  --namespace "$ENFORCER_NAMESPACE" --interface "$ENFORCER_INTERFACE" \
  --destination "$ENFORCER_DESTINATION" --port "$ENFORCER_PORT" \
  --table "${ENFORCER_TABLE:-netcap_firewall_lab}" \
  --protocol "${ENFORCER_PROTOCOL:-tcp}" --hook "${ENFORCER_HOOK:-forward}" \
  --state-file /var/lib/netcap-enforcer/leases.json "$@"
