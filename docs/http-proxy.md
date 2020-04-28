---
description: Inspect traffic to web applications with a HTTP reverse proxy
---

# HTTP Proxy

## Motivation

The **proxy** tool allows to quickly spin up monitoring of web applications and retrieving netcap audit records.

Since currently, TCP stream reassembly is only supported for IPv4, netcap misses HTTP traffic over IPv6 when decoding traffic from raw packets. Also there is currently no support implemented for decoding HTTP2 over TCP or QUIC.

By using a simple reverse proxy for HTTP traffic, the operating system handles the stream reassembly and we can make sure no IPv6 and / or HTTP2 traffic is missed.

## Usage

Spin up a single proxy instance from the commandline:

`$ net proxy -local 127.0.0.1:4000 -remote http://google.com`

Specifiy a custom config file for proxying multiple services with the **-proxy-config** flag:

```text
$ net proxy -proxy-config example_config.yml
```

The default config path is **net.proxy-config.yml**, so if this file exists in the folder where you execute the proxy, you do not need to specify it on the commandline.

## Configuration

For proxying several services, you need to provide a config file, here is a simple example:

```yaml
# Proxies map holds all reverse proxies
proxies:
  service1:
    local: 127.0.0.1:443
    remote: http://127.0.0.1:8080
    tls: true

  service2:
    local: 127.0.0.1:9999
    remote: http://192.168.1.20

  service3:
    local: 127.0.0.1:7000
    remote: https://google.com

# CertFile for TLS secured connections
certFile: "certs/cert.crt"

# KeyFile for TLS secured connections
keyFile: "certs/cert.key"

# Logdir is used as destination for the logfile
logdir: "logs"
```

## Help

```erlang
Usage of net proxy:
  -version bool
        print netcap package version and exit
  -config string
        set config file path (default "net.proxy-config.yml")
  -debug
        set debug mode
  -dialTimeout int
        seconds until dialing to the backend times out (default 30)
  -idleConnTimeout int
        seconds until a connection times out (default 90)
  -local string
        set local endpoint
  -maxIdle int
        maximum number of idle connections (default 120)
  -remote string
        set remote endpoint
  -skipTlsVerify
        skip TLS verification
  -tlsTimeout int
        seconds until a TLS handshake times out (default 15)
```

