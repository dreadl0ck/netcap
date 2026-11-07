# FAQ

## What can I use this for?

The public Go framework turns live packets or PCAP/PCAPNG files into structured
records, browser investigations and reproducible evidence. Start with the
[synthetic capture](quickstart.md) and [protocol coverage](protocol-support.md).

## Does a protocol label mean the payload was decoded?

No. Port names, DPI labels, handshake metadata and complete application parsing
are different capabilities. [Service identification](deep-packet-inspection.md)
describes their boundaries; encrypted payloads need separately supplied plaintext
or secrets for supported experiments.

## Does an alert prove compromise?

No. A rule match, behavioral deviation or NVD applicability candidate needs
validation against its source, scope and asset context. [Evidence](evidence.md)
and [network detections](network-detections.md) show that workflow.

## Can I expose the WebUI publicly?

The local UI/API is unauthenticated. Keep it on loopback or place an appropriate
authenticated hosting boundary in front of it. An MCP token protects `/mcp`, not
every `/api` route; see [Web interface](web-interface.md#hosting-boundary).

## How do I export CSV or JSON?

Use `net dump`, not the Prometheus `net export` command. Follow
[record inspection](filtering-and-export.md).

## How can I contribute to the project?

See [contributing](contributing.md) for the CLA, development setup and tests.

## I have a question, how can I reach you?

Open an issue at [dreadl0ck/netcap](https://github.com/dreadl0ck/netcap/issues)
with version, exact command and error. The maintainer address is
`dreadl0ck [at] protonmail [dot] ch`.
