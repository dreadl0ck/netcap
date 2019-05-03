# NET.COLLECT

*net.collect* is the collection server for receiving audit records from several *net.agent*'s exporting data.

## Description

The collection server decrypts messages adressed to itself from the agents, and writes them to the file system.

Read more about this tool in the documentation: https://docs.netcap.io

## Usage examples

Both collector and agent can be configured by using the -addr flag to specify an IP address and port. To generate a keypair for the server, the -gen-keypair flag must be used:

    $ net.collect -gen-keypair 
    wrote keys
    $ ls
    priv.key pub.key

Start the server:

    $ net.collect -privkey priv.key -addr 127.0.0.1:4200 
    packet-received: bytes=2412 from=127.0.0.1:57368 decoded batch NC_Ethernet from client xyz
    new file xyz/Ethernet.ncap
    packet-received: bytes=2701 from=127.0.0.1:65050 decoded batch NC_IPv4 from client xyz
    new file xyz/IPv4.ncap
    ...

## Help

    $ net.collect -h
        -addr string
                specify an adress and port to listen for incoming traffic (default "127.0.0.1:1335")
        -allowmissinginit
                support streams without SYN/SYN+ACK/ACK sequence
        -assembly_debug_log
                If true, the github.com/google/gopacket/reassembly library will log verbose debugging information (at least one line per packet)
        -assembly_memuse_log
                If true, the github.com/google/gopacket/reassembly library will log information regarding its memory use every once in a while.
        -checksum
                check TCP checksum
        -conn-flush-interval int
                flush connections every X flows (default 10000)
        -conn-timeout int
                close connections older than X seconds (default 60)
        -debug
                display debug information
        -dump
                dump HTTP request/response as hex
        -files string
                path to create file for HTTP 200 OK responses
        -flow-flush-interval int
                flush flows every X flows (default 2000)
        -flow-timeout int
                close flows older than X seconds (default 30)
        -flushevery int
                flush assembler every N packets (default 10000)
        -gen-keypair
                generate keypair
        -ignorefsmerr
                ignore TCP FSM errors
        -memprofile string
                write memory profile
        -nodefrag
                if true, do not do IPv4 defrag
        -nohttp
                disable HTTP parsing
        -nooptcheck
                do not check TCP options (useful to ignore MSS on captures with TSO)
        -privkey string
                path to the hex encoded server private key
        -quiet
                be quiet regarding errors (default true)
        -tcp-close-timeout int
                close tcp streams if older than X seconds (set to 0 to keep long lived streams alive) (default 180)
        -tcp-timeout int
                close streams waiting for packets older than X seconds (default 120)
        -verbose
                be verbose
        -writeincomplete
                write incomplete response