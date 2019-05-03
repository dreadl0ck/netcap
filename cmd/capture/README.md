# NET.CAPTURE

*net.capture* is a commandline tool that provides capturing *Netcap* audit records from PCAP / PCAP-NG files or live from a network interface.

## Description

Traffic can be captured and written to disk with various options, and encoders used to create the audit records can be included or excluded from the generated output.

Read more about this tool in the documentation: https://docs.netcap.io

## Usage examples

Capture from dumpfile:

        $ net.capture -r dump.pcap

Capture from interface:

        $ net.capture -iface eth0

## Help

    $ net.capture -h
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
        -cpuprof
                create cpu profile
        -debug
                display debug information
        -dump
                dump HTTP request/response as hex
        -encoders
                show all available encoders
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
        -overview
                print a list of all available encoders and fields
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
        -snaplen int
                configure snaplen for live capture from interface (default 1024)
        -tcp-close-timeout int
                close tcp streams if older than X seconds (set to 0 to keep long lived streams alive) (default 180)
        -tcp-timeout int
                close streams waiting for packets older than X seconds (default 120)
        -verbose
                be verbose
        -version
                print netcap package version and exit
        -workers int
                number of workers (default 1000)
        -writeincomplete
                write incomplete response