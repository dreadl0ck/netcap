# HTTP Proxy

`net proxy` is an HTTP reverse proxy that records requests handled through it.
It changes the traffic path; it is separate from passive PCAP analysis and does
not provide automatic visibility into all encrypted traffic on a network.

## Usage

For an application you operate at `127.0.0.1:8080`:

```sh
net proxy -local 127.0.0.1:4000 -remote http://127.0.0.1:8080
```

Send test requests to port 4000. Only requests through that listener are proxied.
Upstream TLS verification remains enabled by default; `-skipTlsVerify` weakens
that boundary and is not required for the local HTTP example.

## Configuration

Multiple listeners use the dedicated `-proxy-config` file, whose default path is
`net.proxy-config.yml`. This is different from the generic unimplemented
configuration-generation flags.

```yaml
proxies:
  local-app:
    local: 127.0.0.1:4000
    remote: http://127.0.0.1:8080
logdir: logs
```

```sh
net proxy -proxy-config net.proxy-config.yml
```

TLS listeners additionally use `tls: true` and the top-level `certFile` and
`keyFile`. Supply a certificate appropriate for that listener; this is not a
transparent interception CA.

## Help

Run `net proxy -h` for timeout and trace options. Defaults include a 30-second
dial timeout, 90-second idle timeout and 15-second TLS handshake timeout.
`-dump` prints audit records as JSON; `-trace` is enabled by default.

Historical claims that passive reassembly is IPv4-only are obsolete. Proxy
logging also does not establish complete HTTP/2 or HTTP/3 transaction decoding;
check [protocol coverage](protocol-support.md) for the selected capture path.
