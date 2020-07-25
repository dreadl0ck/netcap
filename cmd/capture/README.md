# NET.CAPTURE

*net capture* is a commandline tool that provides capturing *Netcap* audit records from PCAP / PCAP-NG files or live from a network interface.

## Description

Traffic can be captured and written to disk with various options, and decoders used to create the audit records can be included or excluded from the generated output.

Read more about this tool in the documentation: https://docs.netcap.io

## Usage examples

Capture from dumpfile:

        $ net capture -r dump.pcap

Capture from interface:

        $ net capture -iface eth0

## Help

    $ net capture -h
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
    
    capture tool usage examples:
            $ net capture -read dump.pcap
            $ net capture -iface eth0
    
      -allowmissinginit=false: support streams without SYN/SYN+ACK/ACK sequence
      -base="ethernet": select base layer
      -bpf="": supply a BPF filter to use prior to processing packets with netcap
      -buf=true: buffer data in memory before writing to disk
      -checksum=false: check TCP checksum
      -close-inactive-timeout=24h0m0s: reassembly: close connections that are inactive
      -close-pending-timeout=5s: reassembly: close connections that have pending bytes
      -comp=true: compress output with gzip
      -config="": read configuration from file at path
      -conn-flush-interval=10000: flush connections every X flows
      -conn-timeout=10s: close connections older than X seconds
      -context=true: add packet flow context to selected audit records
      -cpuprof=false: create cpu profile
      -csv=false: output data as CSV instead of audit records
      -debug=false: display debug information
      -dpi=false: use DPI for device profiling
      -decoders=false: show all available decoders
      -exclude="LinkFlow,NetworkFlow,TransportFlow": exclude specific decoders
      -fileStorage="": path to created extracted files (currently only for HTTP)
      -flow-flush-interval=2000: flushes flows every X flows
      -flow-timeout=10s: closes flows older than flowTimeout
      -flushevery=100: flush assembler every N packets
      -free-os-mem=0: free OS memory every X minutes, disabled if set to 0
      -gen-config=false: generate config
      -geoDB=false: use geolocation for device profiling
      -hexdump=false: dump packets used in stream reassembly as hex to the reassembly.log file
      -iface="": attach to network interface and capture in live mode
      -ignore-unknown=true: disable writing unknown packets into a pcap file
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
      -opts="datagrams": select decoding options
      -out="": specify output directory, will be created if it does not exist
      -overview=false: print a list of all available decoders and fields
      -payload=false: capture payload for supported layers
      -pbuf=100: set packet buffer size, for channels that feed data to workers
      -promisc=true: toggle promiscous mode for live capture
      -quiet=false: don't print infos to stdout
      -read="": read specified file, can either be a pcap or netcap audit record file
      -reassemble-connections=true: reassemble TCP connections
      -reverse-dns=false: resolve ips to domains via the operating systems default dns resolver
      -serviceDB=false: use serviceDB for device profiling
      -snaplen=1514: configure snaplen for live capture from interface
      -version=false: print netcap package version and exit
      -wait-conns=true: wait for all connections to finish processing before cleanup
      -workers=12: number of workers
      -writeincomplete=false: write incomplete response