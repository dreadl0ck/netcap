#!/usr/bin/env python3
"""Retain public signed size metadata for bounded snapshot admission tests."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

root = Path(__file__).parent
url = "https://dbs.netcap.io/dbs/signed/v1/latest"
body = subprocess.run(["curl", "--fail", "--silent", "--show-error", "--max-time", "60", "--max-filesize", "2097152", url], capture_output=True, check=True).stdout
envelope = json.loads(body)
cert_bytes = base64.b64decode(envelope["certificate"]["payload"])
anchor = bytes.fromhex("8a6d1aaec22ae69f41430d4109b3293b10f98113df87a0989fa609ffb623d7db")
Ed25519PublicKey.from_public_bytes(anchor).verify(base64.b64decode(envelope["certificate"]["signature"]), cert_bytes)
cert = json.loads(cert_bytes)
payload_bytes = base64.b64decode(envelope["payload"])
Ed25519PublicKey.from_public_bytes(base64.b64decode(cert["public_key"])).verify(base64.b64decode(envelope["signature"]), payload_bytes)
payload = json.loads(payload_bytes)
assert cert["format"] == "netcap-db-signing-key/v1" and payload["channel"] == "community-schema2"
registry = base64.b64decode(payload["registry"])
assert hashlib.sha256(registry).hexdigest() == payload["metadata"]["approval_registry_sha256"]
outputs = [f for review in json.loads(registry) for f in review["outputs"] if f["path"] == "netcap.sqlite"]
assert len(outputs) == 1
receipt = {"source": url, "envelope_sha256": hashlib.sha256(body).hexdigest(), "sequence": payload["sequence"], "sqlite": outputs[0], "qualification": "Authenticated public metadata only; no database body was acquired, copied or approved by this sizing check."}
(root / "snapshot-signed-release.json").write_bytes(body)
(root / "snapshot-sizing-evidence.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
# Export path is resolved explicitly by the caller; never create a sibling checkout.
target = root.parents[1].parent / "netcap-rs/device-catalogues"
assert target.is_dir()
(target / "snapshot-signed-release.json").write_bytes(body)
(target / "snapshot-sizing-evidence.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
print(json.dumps(receipt))
