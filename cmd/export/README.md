# NET.EXPORT

*net export* is a commandline tool that offers exporting prometheus metrics,
either from *Netcap* audit records, PCAP dump files or from live traffic.

## Description

The export tool provides similar functionality to *net.capture*,
but while exporting and serving prometheus metrics on the specified address.
It can be used to export both PCAP and *Netcap* file formats or entire directories of *Netcap* files.

Read more about this tool in the documentation: https://docs.netcap.io

## Usage examples

Read and export PCAP dump file:

    $ net export -r dump.pcap

Read and export metrics live from network interface and disable promisc mode (default: true)

    $ net export -iface eth0 -promisc=false

Read and export *Netcap* dump file:

    $ net export -r TCP.ncap.gz

Read and export *Netcap* dump files in the current directory:

    $ net export .

## Help

    $ net export -h
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
    
    export tool usage examples:
            $ net export -read dump.pcap
            $ net export -iface eth0 -promisc=false
            $ net export -read TCP.ncap.gz
            $ net export .
    
      -address="127.0.0.1:7777": set address for exposing metrics
      -allowmissinginit=false: support streams without SYN/SYN+ACK/ACK sequence
      -base="ethernet": select base layer
      -bpf="": supply a BPF filter to use prior to processing packets with netcap
      -buf=true: buffer data in memory before writing to disk
      -checksum=false: check TCP checksum
      -close-inactive-timeout=24h0m0s: reassembly: close connections that are inactive after X
      -close-pending-timeout=30s: reassembly: close connections that have pending bytes after X
      -comp=true: compress output with gzip
      -config="": read configuration from file at path
      -conn-flush-interval=10000: flush connections every X flows
      -conn-timeout=10s: close connections older than X seconds
      -context=true: add packet flow context to selected audit records
      -csv=false: print output data as csv with header line
      -debug=false: display debug information
      -dir="": path to directory with netcap audit records
      -dpi=false: use DPI for device profiling
      -dumpJson=false: dump as JSON
      -exclude="LinkFlow,TransportFlow,NetworkFlow": exclude specific decoders
      -flow-flush-interval=2000: flushes flows every X flows
      -flow-timeout=10s: closes flows older than flowTimeout
      -flushevery=100: flush assembler every N packets
      -gen-config=false: generate config
      -geoDB=false: use geolocation for device profiling
      -hexdump=false: dump packets used in stream reassembly as hex to the reassembly.log file
      -iface="": attach to network interface and capture in live mode
      -ignore-unknown=false: disable writing unknown packets into a pcap file
      -ignorefsmerr=false: ignore TCP FSM errors
      -include="": include specific decoders
      -interfaces=false: list all visible network interfaces
      -ja3DB=false: use ja3 database for device profiling
      -local-dns=false: resolve DNS locally via hosts file in the database dir
      -macDB=false: use mac to vendor database for device profiling
      -membuf-size=10485760: set size for membuf
      -memprof=false: create memory profile
      -memprofile="": write memory profile
      -nodefrag=false: if true, do not do IPv4 defrag
      -nooptcheck=false: do not check TCP options (useful to ignore MSS on captures with TSO)
      -opts="lazy": select decoding options
      -out="": specify output directory, will be created if it does not exist
      -payload=false: capture payload for supported layers
      -pbuf=100: set packet buffer size, for channels that feed data to workers
      -promisc=true: toggle promiscous mode for live capture
      -read="": read specified file, can either be a pcap or netcap audit record file
      -replay=false: replay traffic (only works when exporting audit records directly!)
      -reverse-dns=false: resolve ips to domains via the operating systems default dns resolver
      -serviceDB=false: use serviceDB for device profiling
      -snaplen=1514: configure snaplen for live capture from interface
      -version=false: print netcap package version and exit
      -wait-conns=true: wait for all connections to finish processing before cleanup
      -workers=12: number of workers
      -writeincomplete=false: write incomplete response
