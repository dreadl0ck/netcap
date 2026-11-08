#!/bin/sh
set -eu
: "${PROBE_SERVER:?TLS server name required}"
code=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
  --connect-timeout 1 --max-time 2 --cacert /probe-ca/ca.crt \
  --header @/probe-auth/authorization --resolve "$PROBE_SERVER:9092:127.0.0.1" \
  "https://$PROBE_SERVER:9092/api/v1/policy-state/health")
test "$code" = 200
