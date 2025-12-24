# NET.COLLECT

*net.collect* is the collection server for receiving audit records from several *net.agent*'s exporting data.

## Description

The collection server decrypts messages adressed to itself from the agents, and writes them to the file system.

Read more about this tool in the documentation: https://docs.netcap.io

## Usage examples

Both collector and agent can be configured by using the -addr flag to specify an IP address and port. To generate a keypair for the server, the -gen-keypair flag must be used:

    $ net collect -gen-keypair 
    wrote keys
    $ ls
    priv.key pub.key

Start the server:

    $ net collect -privkey priv.key -addr 127.0.0.1:4200 
    packet-received: bytes=2412 from=127.0.0.1:57368 decoded batch NC_Ethernet from client xyz
    new file xyz/Ethernet.ncap
    packet-received: bytes=2701 from=127.0.0.1:65050 decoded batch NC_IPv4 from client xyz
    new file xyz/IPv4.ncap
    ...

## Help

    $ net collect -h
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
    
    collect tool usage examples:
            $ net collect -privkey priv.key -addr 127.0.0.1:4200
            $ net collect -gen-keypair
    
      -addr="127.0.0.1:1335": specify an adress and port to listen for incoming traffic
      -config="": read configuration from file at path
      -gen-config=false: generate config
      -gen-keypair=false: generate keypair
      -membuf-size=10485760: set size for membuf
      -privkey="": path to the hex encoded server private key
      -version=false: print netcap package version and exit