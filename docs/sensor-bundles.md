# Signed sensor bundles

`investigate sensor-seal`, `sensor-import` and `sensor-prune` package completed
capture output for a receiving sensor namespace. They are separate from the
live agent/collector TLS transport and from the Ed25519 community database
publisher. Sensor bundles use HMAC-SHA256 shared-key authentication.

## Seal completed output

First run the [synthetic transfer lab](investigation-walkthrough.md).
The fixture generator creates a deterministic 32-byte `sensor.key` solely for
this offline demonstration. It is publicly known and unsuitable for real sensors.

<!-- docs:run sensor-seal -->
```sh
net investigate sensor-seal -read doc-fixtures/audit -out doc-fixtures/sealed \
  -sensor-id docs-lab -key-file doc-fixtures/sensor.key -retention 1h \
  > doc-fixtures/sealed.json
```

The command prints a JSON string containing the published directory path under
`doc-fixtures/sealed/docs-lab/<run-id>/`. The directory contains
`sensor-bundle.json`; do not invent a run ID. The private store is created with mode 0700.
An existing group/world-accessible store is rejected rather than silently fixed.

## Verify and import

<!-- docs:run sensor-import -->
```sh
python3 -c 'import json; print(json.load(open("doc-fixtures/sealed.json")))' > doc-fixtures/bundle-path.txt
net investigate sensor-import -read "$(python3 -c 'print(open("doc-fixtures/bundle-path.txt").read().strip())')" \
  -out doc-fixtures/imported -sensor-id docs-lab -key-file doc-fixtures/sensor.key \
  -retention 1h > doc-fixtures/imported.json
```

The receiver independently supplies the authorized sensor ID, key, byte and
retention limits. The upload cannot authorize its own namespace. Verification
checks manifest authentication, expiry and file hashes; it does not establish
the identity of every endpoint/user named inside the packet evidence.

| Control | Default/requirement |
| --- | --- |
| Key material | 32–4096 bytes read from a file |
| `-max-bytes` | 1 GiB imported bundle bytes |
| `-retention` | 24h default; at most 30 days |
| `-timeout` | 2 minutes |
| Sensor ID | Lowercase ASCII letters/digits with `_`/`-`, maximum 64 characters |

For production, generate and distribute secret random keys through the sensor's
existing credential-management path. HMAC proves possession of a shared secret;
either holder can create a valid bundle. It is not public-key nonrepudiation.

## Prune expired imports

<!-- docs:run sensor-prune -->
```sh
net investigate sensor-prune -out doc-fixtures/imported -sensor-id docs-lab \
  -key-file doc-fixtures/sensor.key -retention 1h > doc-fixtures/pruned.json
```

Pruning removes expired imports in the explicitly authorized namespace; it is a
deletion operation. In this newly created one-hour lab store, nothing should
have expired. Source captures and the seal store have independent retention.
