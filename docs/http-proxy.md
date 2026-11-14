# HTTP reverse proxy

`net proxy` is an HTTP reverse proxy that records every request it forwards. Put it in front of a web app you run, such as a staging server, to get audit records for its traffic. It only sees requests sent through its listener. It does not decrypt other traffic on your network.

## Proxy one application

If your app listens on `127.0.0.1:8080`:

```sh
net proxy -local 127.0.0.1:4000 -remote http://127.0.0.1:8080
```

Send your test requests to port 4000. The proxy verifies TLS certificates of upstream servers. `-skipTlsVerify` turns that off. You do not need it for this plain HTTP example.

## Proxy several applications

For more than one listener, use a config file. The default path is `net.proxy-config.yml`; change it with `-proxy-config`.

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

To serve TLS on a listener, set `tls: true` on it and add `certFile` and `keyFile` at the top level. Use a certificate that is valid for the hostname clients connect to. The proxy does not generate certificates or intercept TLS transparently.

## Options

Run `net proxy -h` for timeout and trace options. The defaults are a 30-second dial timeout, a 90-second idle timeout and a 15-second TLS handshake timeout. `-dump` prints the audit records as JSON, and `-trace` is on by default.

The proxy does not fully decode HTTP/2 or HTTP/3 transactions. See [protocol coverage](protocol-support.md).
