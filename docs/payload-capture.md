# Payload retention

`capture -payload` includes raw payload fields where the selected decoder
supports them. It does not decrypt TLS or recover upstream-truncated packets.

```sh
net capture -read traffic.pcap -out payload-audit -payload -dpi=false
net dump -read payload-audit/UDP.ncap.gz -json
```

JSON represents protobuf byte fields as base64. CSV/custom record renderers may
use another representation; consult the record schema before interpreting a
string as text. Payload field coverage is decoder-specific.

| Option/artifact | Different purpose |
| --- | --- |
| `-payload` | Raw bytes in supported audit records |
| `-conns` | Directional stream evidence and conversation output |
| File extraction | Reconstruct transferred file artifacts with completeness metadata |
| `-retain-packets` | Rotating PCAPNG packet retention with a manifest |

Retained bytes can contain credentials, personal data and executable content.
Set collection, access and retention boundaries for the actual output directory.
Compression is not anonymization. Preserve the original capture for reruns;
missing payloads in an old record require reanalysis from available source bytes.
