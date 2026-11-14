# Payload retention

`capture -payload` stores the raw payload bytes in the audit records of decoders that support it. It does not decrypt TLS, and it cannot recover bytes that the capture tool cut off.

Keep the payload of every UDP packet in a capture, then read it:

```sh
net capture -read office-lan.pcap -out payload-audit -payload -dpi=false
net dump -read payload-audit/UDP.ncap.gz -json
```

JSON shows byte fields as base64. CSV and other renderers may show them differently, so check the record schema before you treat a value as text. Which records carry a payload field depends on the decoder.

| Option            | What it keeps                                            |
| ----------------- | -------------------------------------------------------- |
| `-payload`        | Raw bytes in supported audit records                     |
| `-conns`          | Per-direction stream bytes and conversation output       |
| File extraction   | Files rebuilt from transfers, with completeness metadata |
| `-retain-packets` | Rotating PCAPNG packet files with a manifest             |

Retained bytes can contain credentials, personal data and executables. Decide who may read the output directory and how long you keep it. Compression does not anonymise anything. Keep the original capture, because records written without `-payload` cannot be filled in later. You have to analyse the capture again.
