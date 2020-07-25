# NET.AGENT

*net agent* is a commandline client for exporting batched audit records via UDP to a *net collect* collection server.

## Description

The agent uses the public key of the collection server to encrypt the batched *Netcap* audit records during transmission.

Read more about this tool in the documentation: https://docs.netcap.io

## Usage examples

Both collector and agent can be configured by using the -addr flag to specify an IP address and port. To generate a keypair for the server, the -gen-keypair flag must be used:

    $ net collect -gen-keypair 
    wrote keys
    $ ls
    priv.key pub.key

Start the agent:

    $ net agent -pubkey pub.key -addr 127.0.0.1:4200
    got 126 bytes of type NC_ICMPv6RouterAdvertisement expected [126] got size [73] for type NC_Ethernet
    got 73 bytes of type NC_Ethernet expected [73]
    got size [27] for type NC_ICMPv6
    got size [126] for type NC_ICMPv6RouterAdvertisement
    got 126 bytes of type NC_ICMPv6RouterAdvertisement expected [126] got size [75] for type NC_IPv6
    got 75 bytes of type NC_IPv6 expected [75]
    got 27 bytes of type NC_ICMPv6 expected [27]

## Help

    $ net agent -h
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
    
    agent tool usage examples:
            $ net agent -pubkey pub.key -addr 127.0.0.1:4200
    
      -addr="127.0.0.1:1335": specify the address and port of the collection server
      -allowmissinginit=false: support streams without SYN/SYN+ACK/ACK sequence
      -base="ethernet": select base layer
      -bpf="": supply a BPF filter to use for netcap collection
      -checksum=false: check TCP checksum
      -close-inactive-timeout=24h0m0s: reassembly: close connections that are inactive after X
      -close-pending-timeout=30s: reassembly: close connections that have pending bytes after X
      -config="": read configuration from file at path
      -conn-flush-interval=10000: flush connections every X flows
      -conn-timeout=10s: close connections older than X seconds
      -context=true: add packet flow context to selected audit records
      -debug=false: display debug information
      -dpi=false: use DPI for device profiling
      -decoders=false: show all available decoders
      -exclude="": exclude specific decoders
      -flow-flush-interval=2000: flushes flows every X flows
      -flow-timeout=10s: closes flows older than flowTimeout
      -flushevery=100: flush assembler every N packets
      -gen-config=false: generate config
      -geoDB=false: use geolocation for device profiling
      -hexdump=false: dump packets used in stream reassembly as hex to the reassembly.log file
      -iface="en0": interface
      -ignorefsmerr=false: ignore TCP FSM errors
      -include="": include specific decoders
      -interfaces=false: list all visible network interfaces
      -ja3DB=false: use ja3 database for device profiling
      -local-dns=false: resolve DNS locally via hosts file in the database dir
      -macDB=false: use mac to vendor database for device profiling
      -max=10240: max size of packet
      -membuf-size=10485760: set size for membuf
      -memprofile="": write memory profile
      -nodefrag=false: if true, do not do IPv4 defrag
      -nooptcheck=false: do not check TCP options (useful to ignore MSS on captures with TSO)
      -opts="lazy": select decoding options
      -payload=false: capture payload for supported layers
      -pbuf=0: set packet buffer size
      -promisc=true: capture live in promisc mode
      -pubkey="": path to the hex encoded server public key on disk
      -reverse-dns=false: resolve ips to domains via the operating systems default dns resolver
      -serviceDB=false: use serviceDB for device profiling
      -snaplen=1514: configure snaplen for live capture
      -version=false: print netcap package version and exit
      -wait-conns=true: wait for all connections to finish processing before cleanup
      -workers=12: number of workers
      -writeincomplete=false: write incomplete response