# NET.AGENT

*net.agent* is a commandline client for exporting batched audit records via UDP to a *net.collect* collection server.

## Description

The agent uses the public key of the collection server to encrypt the batched *Netcap* audit records during transmission.

Read more about this tool in the documentation: https://docs.netcap.io

## Usage examples

Both collector and agent can be configured by using the -addr flag to specify an IP address and port. To generate a keypair for the server, the -gen-keypair flag must be used:

    $ net.collect -gen-keypair 
    wrote keys
    $ ls
    priv.key pub.key

Start the agent:

    $ net.agent -pubkey pub.key -addr 127.0.0.1:4200
    got 126 bytes of type NC_ICMPv6RouterAdvertisement expected [126] got size [73] for type NC_Ethernet
    got 73 bytes of type NC_Ethernet expected [73]
    got size [27] for type NC_ICMPv6
    got size [126] for type NC_ICMPv6RouterAdvertisement
    got 126 bytes of type NC_ICMPv6RouterAdvertisement expected [126] got size [75] for type NC_IPv6
    got 75 bytes of type NC_IPv6 expected [75]
    got 27 bytes of type NC_ICMPv6 expected [27]

## Help

    $ net.agent -h
        -addr string
                specify the address and port of the collection server (default "127.0.0.1:1335")
        -allowmissinginit
                support streams without SYN/SYN+ACK/ACK sequence
        -assembly_debug_log
                If true, the github.com/google/gopacket/reassembly library will log verbose debugging information (at least one line per packet)
        -assembly_memuse_log
                If true, the github.com/google/gopacket/reassembly library will log information regarding its memory use every once in a while.
        -base string
                select base layer (default "ethernet")
        -bpf string
                supply a BPF filter to use for netcap collection
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
                interface (default "en0")
        -ignorefsmerr
                ignore TCP FSM errors
        -include string
                include specific encoders
        -max int
                max size of packet (default 10240)
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
        -payload
                capture payload for supported layers
        -pbuf int
                set packet buffer size
        -promisc
                capture live in promisc mode (default true)
        -pubkey string
                path to the hex encoded server public key on disk
        -quiet
                be quiet regarding errors (default true)
        -snaplen int
                configure snaplen for live capture (default 1024)
        -tcp-close-timeout int
                close tcp streams if older than X seconds (set to 0 to keep long lived streams alive) (default 180)
        -tcp-timeout int
                close streams waiting for packets older than X seconds (default 120)
        -verbose
                be verbose
        -workers int
                number of encoder routines (default 100)
        -writeincomplete
                write incomplete response