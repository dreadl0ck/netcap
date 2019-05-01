---
description: Inspect traffic to web applications with a HTTP reverse proxy
---

# HTTP Proxy

### Motivation

The **net.proxy** tool allows to quickly spin up monitoring of web applications and retrieving netcap audit records.

Since currently, TCP stream reassembly is only supported for IPv4, netcap misses HTTP traffic over IPv6 when decoding traffic from raw packets.

By using a simple reverse proxy for HTTP traffic, the operating system handles the stream reassembly and we can make sure no IPv6 traffic is missed.

### Usage

`$ net.proxy -local 127.0.0.1:4000 -remote http://google.com`

### Help

```text
Usage of net.proxy:
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



