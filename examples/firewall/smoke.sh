#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME="netcap-firewall-smoke-${$}"
compose=(docker compose -f compose.yaml)
cleanup() {
  result=$?
  if (( result != 0 )); then "${compose[@]}" logs --no-color >&2 || true; fi
  "${compose[@]}" down --volumes --remove-orphans >&2 || true
  exit "$result"
}
trap cleanup EXIT
"${compose[@]}" config --quiet
if [[ ${SKIP_BUILD:-0} != 1 ]]; then "${compose[@]}" build firewall; fi
"${compose[@]}" run --rm --no-deps firewall validate --config /etc/netcap-firewall/config.yaml
"${compose[@]}" up -d
for ((i=0; i<60; i++)); do
  if "${compose[@]}" exec -T firewall /netcap-firewall healthcheck --url http://127.0.0.1:9090/readyz; then break; fi
  if (( i == 59 )); then exit 1; fi
  sleep 1
done
python3 - <<'PY'
import http.client
import os
import subprocess
import time
import uuid

port = int(os.environ.get('FIREWALL_PORT', '18080'))
nonce = uuid.uuid4().hex
allowed = 'allowed-' + nonce
denied = 'denied-' + nonce
traversal = 'traversal-' + nonce
crs = 'crs-' + nonce

def request(path, chunks=None):
    c = http.client.HTTPConnection('127.0.0.1', port, timeout=20)
    try:
        if chunks is None:
            c.request('GET', path)
        else:
            c.putrequest('POST', path)
            c.putheader('Transfer-Encoding', 'chunked')
            c.endheaders()
            for chunk in chunks:
                c.send(('%x\r\n' % len(chunk)).encode() + chunk + b'\r\n')
                time.sleep(0.1)
            c.send(b'0\r\n\r\n')
        r = c.getresponse()
        body = r.read()
        return r.status, body
    finally:
        c.close()

assert request('/?' + allowed) == (200, b'origin-ok\n'), 'allowed request failed'
assert request('/../blocked?' + traversal)[0] == 403, 'traversal was not denied'
assert request('/?' + denied, [b'x' * 32768, b'netcap-smoke-deny'])[0] == 403, 'late body was not denied'
assert request('/?' + crs + '&q=1%27%20OR%20%271%27=%271')[0] == 403, 'Coraza CRS SQLi was not denied'
time.sleep(0.5)
logs = subprocess.check_output(['docker', 'compose', '-f', 'compose.yaml', 'logs', '--no-color', 'backend'], text=True)
assert logs.count(allowed) == 1, 'origin must receive the allowed request exactly once'
assert all(marker not in logs for marker in (denied, traversal, crs)), 'denied request reached origin'
print('PASS: allowed request reached origin; traversal, late chunked-body and CRS SQLi denial never reached origin')
PY
