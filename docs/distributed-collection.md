---
description: Sensors and Collection Server
---

# Distributed Collection

Sensor agents (`net agent`) capture live traffic and stream audit records to a central collection server (`net collect`). Agents write nothing to disk; the collector writes one `.ncap.gz` per agent and record type, readable with `net dump` like any other netcap file.

![](.gitbook/assets/netcap-iot%20%282%29.svg)

The wire format changed after v0.10.2 and is not compatible with earlier versions, none of which produced readable output: records were sent without length prefixes.

## Transport and authentication

| | |
| --- | --- |
| transport | TCP, TLS 1.3 only |
| authentication | mutual; both sides present a self-signed Ed25519 certificate |
| trust | SHA-256 of the peer's public key (SPKI), pinned like SSH `known_hosts`; no CA |
| client identity | the name in the collector's allowlist for that key. Nothing the agent sends chooses its identity or its output directory |
| delivery | every batch is acknowledged after it is written; the agent resends unacknowledged batches after reconnecting |

After the handshake, each frame is `[1 byte type][4 byte big-endian length][payload]`, capped at 4 MiB by default (`-max-frame`). The cap is checked before anything is allocated.

| frame | direction | payload |
| --- | --- | --- |
| Hello | agent → collector | `types.AgentHello`: protocol version, capture source, session id |
| Batch | agent → collector | `types.Batch`: record type, sequence number, concatenated length-delimited records |
| Ack | collector → agent | 8-byte sequence number |
| Error | collector → agent | reason; the agent drops the rejected batch |

The collector parses every record in a batch before writing it. A batch that fails is answered with an Error frame and never reaches the file. A local write failure closes the connection without an Error frame, so the agent keeps the batch and resends it.

## Setup

Generate the collector identity. It prints the fingerprint that agents pin:

```text
$ net collect -gen-keypair
wrote collector.crt and collector.key
server fingerprint (pass to agents as -server-fingerprint):
189b77182bb198ad6f2bf10d672eb4c6ad5b94a34b5d6b4bb861ccfde290abc1
```

On each sensor, generate an agent identity:

```text
$ net agent -gen-keypair
wrote agent.crt and agent.key
agent fingerprint (add to the collector's -clients file):
b69d2c0a5cac19c3351d422d43ba2b029a91ecdab83fdf3fd2de3716a4039236 <name>
```

Add each agent to the allowlist, one `<fingerprint> <name>` per line. A name is 1-64 characters of `[A-Za-z0-9._-]`. A malformed line, a duplicate key or a duplicate name stops the collector at startup.

```text
# clients.txt
b69d2c0a5cac19c3351d422d43ba2b029a91ecdab83fdf3fd2de3716a4039236 sensor-dmz
```

Start both:

```bash
net collect -clients clients.txt -addr 0.0.0.0:1335 -out collected
net agent -server-fingerprint 189b7718...90abc1 -addr collector:1335 -iface eth0
```

Output goes to `<out>/<name>/<Type>.ncap.gz`, with directories `0750` and files `0640`. A file left by an earlier collector run is never truncated: the next run writes `TCP-1.ncap.gz` and so on. Key files are written `0600`, and `-gen-keypair` refuses to overwrite them.

To revoke an agent, remove its line and restart the collector.

## Agent flags

| flag | default | |
| --- | --- | --- |
| `-max` | 1 MiB | target batch size; a larger single record is sent alone |
| `-flush-interval` | 5s | send a partly filled batch at least this often, so rare record types arrive |
| `-max-pending` | 64 MiB | unacknowledged batches kept in memory while the collector is unreachable; the oldest are dropped beyond this and the drop is logged |
| `-shutdown-timeout` | 30s | how long SIGINT/SIGTERM keeps delivering queued batches |
| `-reassemble-connections` | true | required for every stream decoder (HTTP, SMTP, ...) |

Reconnects use exponential backoff from 1s to 60s. On exit the agent logs how many batches were delivered, rejected, dropped and left undelivered.

## Collector flags

| flag | default | |
| --- | --- | --- |
| `-out` | `collected` | output root |
| `-max-frame` | 4 MiB | largest accepted frame |
| `-max-conns` | 256 | concurrent connections |
| `-idle-timeout` | 5m | close a silent connection; the agent reconnects when it next has data |
| `-shutdown-timeout` | 30s | wait for in-flight batches before closing files |

## Limits

- A record over about 4 MiB cannot be sent. The agent drops it and logs it.
- The resend queue lives in memory. Batches still queued when the agent process dies are lost.
- An ack means the batch has been gzip-flushed to the OS, not fsynced. Batches acknowledged before a collector host crash can be lost.
- A file being written is an unfinished gzip stream: reading it before the collector shuts down ends with `unexpected EOF`.
