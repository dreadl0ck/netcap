# Service identification and DPI

Netcap has four ways to find out what a service is. They answer different questions, so use the one that fits.

| Method                      | Input                          | Result                                                                               |
| --------------------------- | ------------------------------ | ------------------------------------------------------------------------------------ |
| IANA lookup                 | Port and transport             | The service registered for that port                                                 |
| Built-in service signatures | The first bytes a server sends | SSH, HTTP/1, SMTP or FTP, plus the banner fields                                     |
| Native DPI                  | Flow classifier                | An application or category label                                                     |
| NVD lookup                  | Product and version            | CVEs that could apply (see [Vulnerability applicability](vulnerability-analysis.md)) |

The stream decoder also picks a protocol parser by looking at the framing and signatures in the captured bytes.

## Example: SSH on a nonstandard port

A server accepts SSH on port 2222. The IANA port name says nothing about SSH, but the SSH identification string in its greeting does:

```sh
net capture -read traffic.pcap -out classified -dpi=false
net dump -read classified/Service.ncap.gz -csv -select IP,Port,PortName,Name,Product,Version,Banner
```

`PortName` is the IANA result. `Name`, `Product`, `Version` and `Banner` come from the greeting. Pass the product and version on to the [vulnerability check](vulnerability-analysis.md) to see which CVEs apply.

## Choose a build

```sh
net --version
net capture -read traffic.pcap -out classified -dpi=false
```

`net --version` shows whether DPI is compiled in. DPI release archives include the native libraries. A build without DPI cannot enable it with a flag. Run `net capture -h` to see the DPI options, such as `-dpi` and `-dpi-modules lpi,ndpi,go`.

A DPI label names the application. It does not decode the traffic. A TLS or QUIC label does not give you the HTTP content inside.

## Built-in service signatures

Netcap does not use Nmap's `nmap-service-probes`. The built-in signatures (`netcap-service-signatures`, schema 1) recognise:

* SSH identification strings
* HTTP/1 response status lines
* SMTP and FTP greetings

A bare `220` greeting does not separate SMTP from FTP, so Netcap only labels greetings that are clear. The catalogue status lists missing optional inputs.

A custom catalogue uses the same format. Keep it outside the signed archive directory so an update does not overwrite your file.

## Limits

Encrypted traffic, incomplete greetings, ambiguous protocols and gaps in a stream can prevent identification. HASSH and user-agent identification need their local databases. The label comes from what the device announces, so a server can report software it does not run.

See [TLS fingerprinting](tls-fingerprinting.md), [Resolvers](resolvers.md) and [record support](protocol-support.md).
