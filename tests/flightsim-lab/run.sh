#!/usr/bin/env bash
set -euo pipefail
test "$(ip -j route | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')" = 0
printf 'nameserver 127.0.0.1\noptions timeout:1 attempts:1\n' > /etc/resolv.conf
for subnet in 192.0.2.0/24 198.51.100.0/24 203.0.113.0/24; do ip route add local "$subnet" dev lo; done
openssl req -x509 -newkey rsa:2048 -nodes -keyout /lab/key.pem -out /lab/cert.pem -days 1 -subj /CN=flightsim-lab -addext 'subjectAltName=DNS:api.open.wisdom.alphasoc.net,DNS:api.telegram.org' 2>/dev/null
openssl genrsa -traditional -out /lab/ssh-key.pem 2048 2>/dev/null
export SSL_CERT_FILE=/lab/cert.pem GODEBUG=netdns=go
unset FLIGHTSIM_TELEGRAM_TOKEN
python3 /lab/server.py &
server=$!
trap 'kill "$server" 2>/dev/null || true' EXIT
sleep 2
mkdir -p /results
flightsim version > /results/version.txt
for module in ${MODULES:-c2 dga imposter miner scan sink spambot ssh-exfil ssh-transfer tunnel-dns tunnel-icmp irc oast telegram-bot cleartext}; do
    tcpdump -B 32768 -U -n -i lo -w "/results/$module.pcap" > "/results/$module.capture.log" 2>&1 &
    capture=$!
    sleep 0.3
    scenario=$module
    size=15
    if [[ $module == scan ]]; then size=3; fi
    if [[ $module == ssh-exfil || $module == ssh-transfer ]]; then scenario="$module:1MB"; fi
    timeout 40 flightsim run -fast -size "$size" -iface 127.0.0.1 "$scenario" > "/results/$module.log" 2>&1 || { kill -INT "$capture"; wait "$capture"; exit 1; }
    sleep 2
    kill -INT "$capture"
    wait "$capture"
    test "$(stat -c %s "/results/$module.pcap")" -gt 24
done
python3 - <<'PY'
import hashlib,json,pathlib
root=pathlib.Path('/results')
for path in root.glob('*.capture.log'):
    assert '0 packets dropped by kernel' in path.read_text(), path
for path in root.glob('*.log'):
    if path.name.endswith('.capture.log'): continue
    text=path.read_text()
    assert 'Done (' in text and 'ERROR:' not in text and 'FATAL:' not in text, path
files={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.iterdir()) if p.suffix in ('.pcap','.log','.txt')}
(root/'manifest.json').write_text(json.dumps({'contract':1,'origin':'pinned FlightSim CLI in Docker --network none; local DNS/API/SSH/SFTP/IRC/Stratum fixtures','revision':'3709d1c6905d9527885c62f66f49a955c7b0d191','commands':'flightsim run -fast -size 15 -iface 127.0.0.1 MODULE; scan -size 3; SSH scopes :1MB','binarySHA256':hashlib.sha256(pathlib.Path('/usr/local/bin/flightsim').read_bytes()).hexdigest(),'sha256':files},indent=2)+'\n')
PY
