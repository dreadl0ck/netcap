# NET.PROXY

*net.proxy* is a commandline tool that offers creation of one or several HTTP reverse proxies,
in order to gather *Netcap* audit records from them.

## Description

A file for each proxy will be created that contains HTTP audit records.
Multiple proxies can be configured with a YAML config file.

The naming scheme is HTTP[remoteURL].ncap.gz, e.g: HTTP[github.com].ncap.gz

Read more about this tool in the documentation: https://docs.netcap.io

## Usage examples

Use a single reverse proxy:

    $ net.proxy -local 127.0.0.1:4444 -remote https://github.com

Specify maximum number of idle connections:

	$ net.proxy -local 127.0.0.1:4444 -remote https://github.com -maxIdle 300

Dump audit records while capturing:

    $ net.proxy -local 127.0.0.1:4444 -remote https://github.com -dump

## Help

    $ net.proxy -h
        -config string
                set config file path (default "net.proxy-config.yml")
        -debug
                set debug mode
        -dialTimeout int
                seconds until dialing to the backend times out (default 30)
        -dump
                dumps audit record as JSON to stdout
        -format
                format when dumping JSON (default true)
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
        -trace
                trace HTTP requests to retrieve additional information (default true)