#!/usr/bin/env bash
set -euo pipefail
: "${NETCAP_BIN:?set NETCAP_BIN to the capture executable}"
net() { "$NETCAP_BIN" "$@"; }
api() { curl -fsS -H "Authorization: Bearer ${NETCAP_DOCS_TOKEN:?local API token unavailable}" "$@"; }

case "${1:-}" in
fixtures)
    python3 scripts/docs-fixtures.py
    ;;
investigation)
    net capture -read doc-fixtures/investigation.pcap -out doc-fixtures/audit \
        -rules docs/examples/http-observation.yml -conns -dpi=false -geoDB=false
    for type in DNS HTTP File Alert; do
        case "$type" in DNS) name=dns;; HTTP) name=http;; File) name=files;; Alert) name=alerts;; esac
        net dump -read "doc-fixtures/audit/$type.ncap.gz" -json > "doc-fixtures/$name.ndjson"
    done
    ;;
related)
    net investigate related -read doc-fixtures/audit -type HTTP -ordinal 0 > doc-fixtures/related.json
    ;;
control)
    net capture -read doc-fixtures/benign.pcap -out doc-fixtures/control \
        -rules docs/examples/http-observation.yml -dpi=false -geoDB=false
    ;;
packet-export)
    net investigate packet-evidence -read doc-fixtures/investigation.pcap \
        -bpf 'host 192.0.2.10 and tcp port 8080' -out doc-fixtures/http-evidence.zip
    ;;
network-policy)
    net capture -read doc-fixtures/investigation.pcap -out doc-fixtures/policy-audit \
        -network-detection-config docs/examples/network-detection.json -dpi=false -geoDB=false
    ;;
grammar)
    net investigate protocol-fields -spec docs/examples/grammar.json \
        -read doc-fixtures/client.bin -compare doc-fixtures/other-client.bin > doc-fixtures/grammar-comparison.json
    ;;
sensor-seal)
    net investigate sensor-seal -read doc-fixtures/audit -out doc-fixtures/sealed \
        -sensor-id docs-lab -key-file doc-fixtures/sensor.key -retention 1h > doc-fixtures/sealed.json
    ;;
sensor-import)
    bundle=$(python3 -c 'import json; print(json.load(open("doc-fixtures/sealed.json")))')
    net investigate sensor-import -read "$bundle" -out doc-fixtures/imported \
        -sensor-id docs-lab -key-file doc-fixtures/sensor.key -retention 1h > doc-fixtures/imported.json
    ;;
sensor-prune)
    net investigate sensor-prune -out doc-fixtures/imported -sensor-id docs-lab \
        -key-file doc-fixtures/sensor.key -retention 1h > doc-fixtures/pruned.json
    ;;
baseline)
    exec "$NETCAP_BIN" capture -read doc-fixtures/baseline.pcap -out doc-fixtures/baseline-audit \
        -behavior -behavior-sensor docs-lab -behavior-prefix 192.0.2.0/24 \
        -behavior-learning 1s -behavior-min-samples 4 -dpi=false -geoDB=false -http 127.0.0.1:8080
    ;;
approve-baseline)
    api http://127.0.0.1:8080/api/behavior > doc-fixtures/learning.json
    python3 -c 'import json; s=json.load(open("doc-fixtures/learning.json")); assert s["mode"] == "learning" and s["samples"] >= 4 and s["observed"]; json.dump({"action":"approve","ids":[],"reason":"Reviewed synthetic ARP lab only","version":s["version"]},open("doc-fixtures/approve.json","w"))'
    api -H 'Content-Type: application/json' --data-binary @doc-fixtures/approve.json \
        http://127.0.0.1:8080/api/behavior/change > doc-fixtures/approved.json
    python3 -c 'import json; s=json.load(open("doc-fixtures/approved.json")); assert s["mode"] == "monitoring" and s["approved"]'
    ;;
monitor-baseline)
    net capture -read doc-fixtures/unchanged.pcap -out doc-fixtures/unchanged-audit \
        -behavior-baseline doc-fixtures/baseline-audit/Behavior.json -behavior-sensor docs-lab -behavior-prefix 192.0.2.0/24 -dpi=false -geoDB=false
    net capture -read doc-fixtures/changed.pcap -out doc-fixtures/changed-audit \
        -behavior-baseline doc-fixtures/baseline-audit/Behavior.json -behavior-sensor docs-lab -behavior-prefix 192.0.2.0/24 -dpi=false -geoDB=false
    net dump -read doc-fixtures/changed-audit/Alert.ncap.gz -json > doc-fixtures/behavior-alerts.ndjson
    ;;
yara)
    exec "$NETCAP_BIN" capture -read doc-fixtures/investigation.pcap -out doc-fixtures/yara-audit \
        -http 127.0.0.1:8080 -dpi=false -geoDB=false
    ;;
yara-scan)
    api http://127.0.0.1:8080/api/yara/status > doc-fixtures/yara-status.json
    python3 -c 'import json; assert json.load(open("doc-fixtures/yara-status.json"))["available"]'
    api -F file=@docs/examples/synthetic-file.yar http://127.0.0.1:8080/api/yara/rules/upload > doc-fixtures/yara-upload.json
    net dump -read doc-fixtures/yara-audit/File.ncap.gz -json > doc-fixtures/yara-files.ndjson
    python3 -c 'import json,pathlib; r=json.loads(open("doc-fixtures/yara-files.ndjson").readline()); p=pathlib.Path(r["Location"]).resolve(); base=pathlib.Path("doc-fixtures/yara-audit/files").resolve(); json.dump({"filePath":str(p.relative_to(base))},open("doc-fixtures/yara-request.json","w")); (base/"negative.txt").write_text("Synthetic negative scanner control.\n")'
    api -H 'Content-Type: application/json' --data-binary @doc-fixtures/yara-request.json \
        http://127.0.0.1:8080/api/yara/scan-file > doc-fixtures/yara-positive.json
    api -H 'Content-Type: application/json' --data-binary '{"filePath":"negative.txt"}' \
        http://127.0.0.1:8080/api/yara/scan-file > doc-fixtures/yara-negative.json
    ;;
*)
    printf 'Unknown documentation workflow: %s\n' "${1:-}" >&2
    exit 2
    ;;
esac
