# NET.EXPORT

*net.export* is a commandline tool that offers exporting prometheus metrics,
either from *Netcap* audit records, PCAP dump files or from live traffic.

## Description

The export tool provides similar functionality to *net.capture*,
but while exporting and serving prometheus metrics on the specified address.
It can be used to export both PCAP and *Netcap* file formats or entire directories of *Netcap* files.

Read more about this tool in the documentation: https://docs.netcap.io

## Usage examples

Read and export PCAP dump file:

    $ net.export -r dump.pcap

Read and export metrics live from network interface and disable promisc mode (default: true)

    $ net.export -iface eth0 -promisc=false

Read and export *Netcap* dump file:

    $ net.export -r TCP.ncap.gz

Read and export *Netcap* dump files in the current directory:

    $ net.export .

## Help

    $ net.export -h
        -address string
            set address for exposing metrics (default "127.0.0.1:7777")
        -allowmissinginit
                support streams without SYN/SYN+ACK/ACK sequence
        -assembly_debug_log
                If true, the github.com/google/gopacket/reassembly library will log verbose debugging information (at least one line per packet)
        -assembly_memuse_log
                If true, the github.com/google/gopacket/reassembly library will log information regarding its memory use every once in a while.
        -base string
                select base layer (default "ethernet")
        -bpf string
                supply a BPF filter to use prior to processing packets with netcap
        -buf
                buffer data in memory before writing to disk (default true)
        -checksum
                check TCP checksum
        -comp
                compress output with gzip (default true)
        -conn-flush-interval int
                flush connections every X flows (default 10000)
        -conn-timeout int
                close connections older than X seconds (default 60)
        -debug
                display debug information
        -dump
                dump HTTP request/response as hex
        -dumpJson
                dump as JSON
        -exclude string
                exclude specific encoders
        -files string
                path to create file for HTTP 200 OK responses
        -flow-flush-interval int
                flush flows every X flows (default 2000)
        -flow-timeout int
                close flows older than X seconds (default 30)
        -flushevery int
                flush assembler every N packets (default 10000)
        -iface string
                attach to network interface and capture in live mode
        -ignore-unknown
                disable writing unknown packets into a pcap file
        -ignorefsmerr
                ignore TCP FSM errors
        -include string
                include specific encoders
        -logo
                show netcap logo (default true)
        -memprof
                create memory profile
        -memprofile string
                write memory profile
        -nodefrag
                if true, do not do IPv4 defrag
        -nohttp
                disable HTTP parsing
        -nooptcheck
                do not check TCP options (useful to ignore MSS on captures with TSO)
        -opts string
                select decoding options (default "lazy")
        -out string
                specify output directory, will be created if it does not exist
        -payload
                capture payload for supported layers
        -pbuf int
                set packet buffer size, for channels that feed data to workers (default 100)
        -promisc
                toggle promiscous mode for live capture (default true)
        -quiet
                be quiet regarding errors (default true)
        -r string
                read specified file, can either be a pcap or netcap audit record file
        -replay
                replay traffic (default true)
        -snaplen int
                configure snaplen for live capture from interface (default 1024)
        -tcp-close-timeout int
                close tcp streams if older than X seconds (set to 0 to keep long lived streams alive) (default 180)
        -tcp-timeout int
                close streams waiting for packets older than X seconds (default 120)
        -verbose
                be verbose
        -workers int
                number of workers (default 1000)
        -writeincomplete
                write incomplete response