<a href="https://github.com/dreadl0ck/netcap">
  <img src="graphics/svg/Netcap-Logo.svg" width="100%" height="144">
</a>

<br>
<br>
<br>

The **Netcap** (NETwork CAPture) framework efficiently converts a stream of network packets into highly accessible type-safe structured data that represent specific protocols or custom abstractions.
These audit records can be stored on disk or exchanged over the network,
and are well suited as a data source for machine learning algorithms.
Since parsing of untrusted input can be dangerous and network data is potentially malicious,
implementation was performed in a programming language that provides a garbage collected memory safe runtime.

[![asciicast](https://asciinema.org/a/isjf9sjMhwFubMhI4bltEWS8g.svg)](https://asciinema.org/a/isjf9sjMhwFubMhI4bltEWS8g)

It was developed for a series of experiments in my bachelor thesis: _Implementation and evaluation of secure and scalable anomaly-based network intrusion detection_.
Currently, the thesis serves as documentation until the wiki is ready - it is included at the root of this repository (file: [mied18.pdf](https://github.com/dreadl0ck/netcap/blob/master/mied18.pdf)), slides from my presentation are available on [researchgate](https://www.researchgate.net/project/Anomaly-based-Network-Security-Monitoring).

The project won the 2nd Place at Kaspersky Labs SecurIT Cup 2018 in Budapest.

**Netcap** uses Google's Protocol Buffers to encode its output, which allows accessing it across a wide range of programming languages.
Alternatively, output can be emitted as comma separated values, which is a common input format for data analysis tools and systems.
The tool is extensible and provides multiple ways of adding support for new protocols, 
while implementing the parsing logic in a memory safe way.
It provides high dimensional data about observed traffic and allows the researcher to focus on experimenting with novel approaches for detecting malicious behavior in network environments,
instead of fiddling with data collection mechanisms and post processing steps.
It has a concurrent design that makes use of multi-core architectures.
The name **Netcap** was chosen to be simple and descriptive.
The command-line tool was designed with usability and readability in mind,
and displays progress when processing packets.

## Design Goals

- memory safety when parsing untrusted input
- ease of extension
- output format interoperable with many different programming languages
- concurrent design
- output with small storage footprint on disk
- maximum data availability
- allow implementation of custom abstractions
- rich platform and architecture support

The following graphic shows a high level architecture overview:

<br>
<img src="graphics/svg/Netcap.svg" width="100%" height="100%">
<br>

Packets are fetched from an input source (offline dump file or live from an interface) and distributed via round-robin to a pool of workers. Each worker dissects all layers of a packet and writes the generated protobuf audit records to the corresponding file. By default, the data is compressed with gzip to save storage space and buffered to avoid an overhead due to excessive syscalls for writing data to disk.

## Specification

Netcap files have the file extension **.ncap** or **.ncap.gz** if compressed with gzip and contain serialized protocol buffers of one type.  Naming of each file happens according to the naming in the gopacket library:  a short uppercase letter representation for common protocols, anda camel case version full word version for less common protocols.  Audit records are modeled as protocol buffers.  Each file contains a header that specifies which type of audit records is inside the file, what version of Netcap was used to generate it, what input source was used and what time it was created.  Each audit record should be tagged with the timestamp the packet was seen,  in the format seconds.microseconds.  Output is written to a file that represents each data structure from the protocol buffers definition, i.e. TCP.ncap, UDP.ncap. For this purpose, the audit records are written as length delimited records into the file.

## Quickstart

Read traffic live from interface, stop with Ctrl-C (SIGINT): 

    $ netcap -iface eth0

Read traffic from a dump file (supports PCAP or PCAPNG):

    $ netcap -r traffic.pcap

Read a netcap dumpfile and print to stdout as CSV:

    $ netcap -r TCP.ncap.gz

Show the available fields for a specific Netcap dump file: 

    $ netcap -fields -r TCP.ncap.gz

Print only selected fields and output as CSV:

    $ netcap -r TCP.ncap.gz -select Timestamp,SrcPort,DstPort

Save CSV output to file:

    $ netcap -r TCP.ncap.gz -select Timestamp,SrcPort,DstPort > tcp.csv

Print output separated with tabs:

    $ netcap -r TPC.ncap.gz -tsv

Run with 24 workers and disable gzip compression and buffering:

    $ netcap -workers 24 -buf false -comp false -r traffic.pcapng

Parse pcap and write all data to output directory (will be created if it does not exist):

    $ netcap -r traffic.pcap -out traffic_ncap

Convert timestamps to UTC:

    $ netcap -r TCP.ncap.gz -select Timestamp,SrcPort,Dstport -utc

## Tests

To execute the unit tests, run the followig from the project root:

    go test -v -bench=. ./...

## Audit Records

### Supported Protocols

| Name                        | Layer       | Description                |
| --------------------------- | ----------- | -------------------------- |
| Ethernet                    | Link        | IEEE 802.3 Ethernet Protocol               |
| ARP                         | Link        | Address Resolution Procotol               |
| Dot1Q                       | Link        | IEEE 802.1Q, virtual LANs on an Ethernet network               |
| Dot11                       | Link        | IEEE 802.11 Wireless LAN               |
| LinkLayerDiscovery          | Link        | IEEE 802.1AB Station and Media Access Control Connectivity Discovery               |
| EthernetCTP                 | Link        | diagnostic protocol included in the Xerox Ethernet II specification               |
| EthernetCTPReply            | Link        | reply to an ethernet ctp packet               |
| LinkLayerDiscoveryInfo      | Link        | decoded details for a set of LinkLayerDiscoveryValues               |
| LLC                         | Link        | IEEE 802.2 LLC               |
| SNAP                        | Link        | mechanism for multiplexing, on networks using IEEE 802.2 LLC               |
| IPv4                        | Network     | Internet Protocol version 4               |
| IPv6                        | Network     | Internet Protocol version 6              |
| IPv6HopByHop                | Network     | IPv6 Hop-by-Hop Header               |
| IGMP                        | Network     | Internet Group Management Protocol               |
| ICMPv4                      | Network     | Internet Control Message Protocol v4               |
| ICMPv6                      | Network     | Internet Control Message Protocol v6               |
| ICMPv6NeighborAdvertisement | Network     | Neighbor Discovery Protocol               |
| ICMPv6RouterAdvertisement   | Network     | Neighbor Discovery Protocol               |
| ICMPv6Echo                  | Network     | Neighbor Discovery Protocol               |
| ICMPv6NeighborSolicitation  | Network     | Neighbor Discovery Protocol               |
| ICMPv6RouterSolicitation    | Network     | Neighbor Discovery Protocol               |
| UDP                         | Transport   | User Datagram Protocol               |
| TCP                         | Transport   | Transmission Control Protocol               |
| SCTP                        | Transport   | Stream Control Transmission Protocol               |
| DNS                         | Application | Domain Name System               |
| DHCPv4                      | Application | Dynamic Host Configuration version 4               |
| DHCPv6                      | Application | Dynamic Host Configuration version 6               |
| NTP                         | Application | Network Time Protocol               |
| SIP                         | Application | Session Initiation Protocol               |
| HTTP                        | Application | Hypertext Transfer Protocol              |

### Protocol Sub Structure Types

| Name                        | Description               |
| --------------------------- | ------------------------- |
| Dot11QOS                    | IEEE 802.11 Quality Of Service              |
| Dot11HTControl              | IEEE 802.11 HTC information              |
| Dot11HTControlVHT           | IEEE 802.11 HTC information              |
| Dot11HTControlHT            | IEEE 802.11 HTC information              |
| Dot11HTControlMFB           | IEEE 802.11 HTC information              |
| Dot11LinkAdapationControl   | IEEE 802.11 HTC information              |
| Dot11ASEL                   | IEEE 802.11 HTC information              |
| LLDPChassisID               | Link Layer Discovery Protocol information              |
| LLDPPortID                  | Link Layer Discovery Protocol information              |
| LinkLayerDiscoveryValue     | Link Layer Discovery Protocol information              |
| LLDPSysCapabilities         | Link Layer Discovery Protocol information              |
| LLDPCapabilities            | Link Layer Discovery Protocol information              |
| LLDPMgmtAddress             | Link Layer Discovery Protocol information              |
| LLDPOrgSpecificTLV          | Link Layer Discovery Protocol information              |
| IPv4Option                  | IPv4 option              |
| ICMPv6Option                | ICMPv6 option              |
| TCPOption                   | TCP option              |
| DNSResourceRecord           | Domain Name System resource record              |
| DNSSOA                      | Domain Name System start of authority record              |
| DNSSRV                      | Domain Name System service record              |
| DNSMX                       | Mail exchange record              |
| DNSQuestion                 | Domain Name System request for a single domain              |
| DHCPOption                  | DHCP v4 option              |
| DHCPv6Option                | DHCP v6 option              |
| IGMPv3GroupRecord           | IGMPv3 group records for a membership report              |
| IPv6HopByHopOption          | IPv6 hop by hop extension TLV option              |
| IPv6HopByHopOptionAlignment | Hop By Hop Option Alignment             |


## Available Fields

### Layer Encoders

| Layer                         | NumFields | Fields               |
| ----------------------------- | ---------- | -------------------- |
| TCP                           | 22        | Timestamp, SrcPort, DstPort, SeqNum, AckNum, DataOffset, FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS, Window, Checksum, Urgent, Padding, Options, PayloadEntropy, PayloadSize             |
| UDP                           |  7        | Timestamp, SrcPort, DstPort, Length, Checksum, PayloadEntropy, PayloadSize             |
| IPv4                          | 17        | Timestamp, Version, IHL, TOS, Length, Id, Flags, FragOffset, TTL, Protocol, Checksum, SrcIP, DstIP, Padding, Options, PayloadEntropy, PayloadSize             |
| IPv6                          | 12        | Timestamp, Version, TrafficClass, FlowLabel, Length, NextHeader, HopLimit, SrcIP, DstIP, PayloadEntropy, PayloadSize, HopByHop             |
| DHCPv4                        | 16        | Timestamp, Operation, HardwareType, HardwareLen, HardwareOpts, Xid, Secs, Flags, ClientIP, YourClientIP, NextServerIP, RelayAgentIP, ClientHWAddr, ServerName, File, Options             |
| DHCPv6                        |  7        | Timestamp, MsgType, HopCount, LinkAddr, PeerAddr, TransactionID, Options             |
| ICMPv4                        |  5        | Timestamp, TypeCode, Checksum, Id, Seq             |
| ICMPv6                        |  3        | Timestamp, TypeCode, Checksum             |
| ICMPv6Echo                    |  3        | Timestamp, Identifier, SeqNumber             |
| ICMPv6NeighborSolicitation    |  3        | Timestamp, TargetAddress, Options             |
| ICMPv6RouterSolicitation      |  2        | Timestamp, Options             |
| DNS                           | 18        | Timestamp, ID, QR, OpCode, AA, TC, RD, RA, Z, ResponseCode, QDCount, ANCount, NSCount, ARCount, Questions, Answers, Authorities, Additionals             |
| ARP                           | 10        | Timestamp, AddrType, Protocol, HwAddressSize, ProtAddressSize, Operation, SrcHwAddress, SrcProtAddress, DstHwAddress, DstProtAddress             |
| Ethernet                      |  6        | Timestamp, SrcMAC, DstMAC, EthernetType, PayloadEntropy, PayloadSize             |
| Dot1Q                         |  5        | Timestamp, Priority, DropEligible, VLANIdentifier, Type             |
| Dot11                         | 14        | Timestamp, Type, Proto, Flags, DurationID, Address1, Address2, Address3, Address4, SequenceNumber, FragmentNumber, Checksum, QOS, HTControl             |
| NTP                           | 15        | Timestamp, LeapIndicator, Version, Mode, Stratum, Poll, Precision, RootDelay, RootDispersion, ReferenceID, ReferenceTimestamp, OriginTimestamp, ReceiveTimestamp, TransmitTimestamp, ExtensionBytes             |
| SIP                           |  3        | Timestamp, OrganizationalCode, Type             |
| IGMP                          | 13        | Timestamp, Type, MaxResponseTime, Checksum, GroupAddress, SupressRouterProcessing, RobustnessValue, IntervalTime, SourceAddresses, NumberOfGroupRecords, NumberOfSources, GroupRecords, Version             |
| LLC                           |  6        | Timestamp, DSAP, IG, SSAP, CR, Control             |
| IPv6HopByHop                  |  2        | Timestamp, Options             |
| SCTP                          |  5        | Timestamp, SrcPort, DstPort, VerificationTag, Checksum             |
| SNAP                          |  3        | Timestamp, OrganizationalCode, Type             |
| LinkLayerDiscovery            |  5        | Timestamp, ChassisID, PortID, TTL, Values             |
| ICMPv6NeighborAdvertisement   |  4        | Timestamp, Flags, TargetAddress, Options             |
| ICMPv6RouterAdvertisement     |  7        | Timestamp, HopLimit, Flags, RouterLifetime, ReachableTime, RetransTimer, Options             |
| EthernetCTP                   |  2        | Timestamp, SkipCount             |
| EthernetCTPReply              |  4        | Timestamp, Function, ReceiptNumber, Data             |
| LinkLayerDiscoveryInfo        |  8        | Timestamp, PortDescription, SysName, SysDescription, SysCapabilities, MgmtAddress, OrgTLVs, Unknown             |

### Custom Encoders

| Name                        | NumFields  |  Fields   |
| --------- | ---------| --------- |
| TLS                         |  27        | Timestamp, Type, Version, MessageLen, HandshakeType, HandshakeLen, HandshakeVersion, Random, SessionIDLen, SessionID, CipherSuiteLen, ExtensionLen, SNI, OSCP, CipherSuites, CompressMethods, SignatureAlgs, SupportedGroups, SupportedPoints, ALPNs, Ja3, SrcIP, DstIP, SrcMAC, DStMAC, SrcPort, DstPort |
| LinkFlow                    |  9         | TimestampFirst, TimestampLast, Proto, SrcMAC, DstMAC, Size, NumPackets, UID, Duration |
| NetworkFlow                 |  9         | TimestampFirst, TimestampLast, Proto, SrcIP, DstIP, Size, NumPackets, UID, Duration |
| TransportFlow               |  9         | TimestampFirst, TimestampLast, Proto, SrcPort, DstPort, Size, NumPackets, UID, Duration |
| HTTP                        |  14        | Timestamp, Proto, Method, Host, UserAgent, Referer, ReqCookies, ReqContentLength, URL, ResContentLength, ContentType, StatusCode, SrcIP, DstIP |
| Flow                        |  17        | TimestampFirst, LinkProto, NetworkProto, TransportProto, ApplicationProto, SrcMAC, DstMAC, SrcIP, SrcPort, DstIP, DstPort, Size, AppPayloadSize, NumPackets, UID, Duration, TimestampLast |
| Connection                  |  17        | TimestampFirst, LinkProto, NetworkProto, TransportProto, ApplicationProto, SrcMAC, DstMAC, SrcIP, SrcPort, DstIP, DstPort, Size, AppPayloadSize, NumPackets, UID, Duration, TimestampLast |

## License

GPLv3