# NET.PROXY

*net proxy* is a commandline tool that offers creation of one or several HTTP reverse proxies,
in order to gather *Netcap* audit records from them.

## Description

A file for each proxy will be created that contains HTTP audit records.
Multiple proxies can be configured with a YAML config file.

The naming scheme is HTTP[remoteURL].ncap.gz, e.g: HTTP[github.com].ncap.gz

Read more about this tool in the documentation: https://docs.netcap.io

## Usage examples

Use a single reverse proxy:

    $ net proxy -local 127.0.0.1:4444 -remote https://github.com

Specify maximum number of idle connections:

	$ net proxy -local 127.0.0.1:4444 -remote https://github.com -maxIdle 300

Dump audit records while capturing:

    $ net proxy -local 127.0.0.1:4444 -remote https://github.com -dump
    
## Help

> Caution when supplying the config for this tool: for the proxy configuration use the proxy-config, to overwrite the commandline flags use -config!

    $ net proxy -h
                           / |
     _______    ______   _10 |_     _______   ______    ______
    /     / \  /    / \ / 01/  |   /     / | /    / \  /    / \
    0010100 /|/011010 /|101010/   /0101010/  001010  |/100110  |
    01 |  00 |00    00 |  10 | __ 00 |       /    10 |00 |  01 |
    10 |  01 |01001010/   00 |/  |01 \_____ /0101000 |00 |__10/|
    10 |  00 |00/    / |  10  00/ 00/    / |00    00 |00/   00/
    00/   10/  0101000/    0010/   0010010/  0010100/ 1010100/
                                                      00 |
    Network Protocol Analysis Framework               00 |
    created by Philipp Mieden, 2018                   00/
    v0.5
    
    proxy tool usage examples:
            $ net proxy -local 127.0.0.1:4444 -remote https://github.com
            $ net proxy -local 127.0.0.1:4444 -remote https://github.com -maxIdle 300
            $ net proxy -local 127.0.0.1:4444 -remote https://github.com -dump
    
      -config="": read configuration from file at path
      -debug=false: set debug mode
      -dialTimeout=30: seconds until dialing to the backend times out
      -dump=false: dumps audit record as JSON to stdout
      -format=true: format when dumping JSON
      -gen-config=false: generate config
      -idleConnTimeout=90: seconds until a connection times out
      -local="": set local endpoint
      -maxIdle=120: maximum number of idle connections
      -membuf-size=10485760: set size for membuf
      -proxy-config="net.proxy-config.yml": set config file path
      -remote="": set remote endpoint
      -skipTlsVerify=false: skip TLS verification
      -tlsTimeout=15: seconds until a TLS handshake times out
      -trace=true: trace HTTP requests to retrieve additional information
      -version=false: print netcap package version and exit
