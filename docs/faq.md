# FAQ

## What can I use this for?

Netcap turns live traffic or PCAP/PCAPNG files into structured records, browser investigations and reproducible evidence. Typical jobs are reading an incident PCAP to see who talked to whom, listing the DNS names and HTTP requests in a capture, and matching detected software against known CVEs. Start with the [first capture](quickstart.md) and the [protocol coverage](protocol-support.md).

## My capture is 20 GB. How do I run it without running out of memory?

Use fewer workers, turn DPI off if you do not need it, and cap the TCP payload that readers may hold:

```sh
net capture -read big.pcap -out big-audit -workers 4 -dpi=false \
  -max-retained-tcp-bytes 2147483648
```

This allows 2 GiB of retained TCP payload. It is not a limit on total memory: reassembly pages and decoder caches are counted separately. If the limit is reached, the capture stops with an error instead of finishing. [Workers and resource budgets](workers.md) lists all limits.

## Port 443 shows up as TLS. Why are there no HTTP records?

A port number or DPI label only says which protocol is likely in use. The HTTP inside a TLS connection is encrypted, so Netcap can only decode it if you supply the plaintext or the session secrets for a supported case. [Service identification](deep-packet-inspection.md) explains how services are identified.

## A rule fired on a server. Is it compromised?

Not necessarily. A CVE match from a service banner can be a false positive, for example when a distribution has backported the fix without changing the version string. Check a rule match, a behavioral deviation or an NVD match against its source, scope and what the asset is. [Evidence](evidence.md) and [network detections](network-detections.md) show how.

## Can I expose the WebUI publicly?

Not as it is. The local UI and API have no authentication. Keep them on loopback, or put an authenticating proxy in front. An MCP token protects `/mcp` only, not the other `/api` routes. See [Web interface](web-interface.md#hosting-boundary).

## How do I export CSV or JSON?

Use `net dump`. `net export` serves Prometheus metrics and does not write CSV.

```sh
net dump -read analysis/Connection.ncap.gz -csv
net dump -read analysis/Connection.ncap.gz -json
```

See [record inspection](filtering-and-export.md) for field selection and filters.

## How can I contribute to the project?

See [contributing](contributing.md) for the CLA, development setup and tests.

## I have a question, how can I reach you?

Open an issue at [dreadl0ck/netcap](https://github.com/dreadl0ck/netcap/issues) and include the version, the exact command and the error. You can also write to `dreadl0ck [at] protonmail [dot] ch`.
