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

It was developed for a series of experiments in my bachelor thesis: "Implementation and evaluation of secure and scalable anomaly-based network intrusion detection".
Currently, the thesis serves as documentation until the wiki is ready.

The project won the 2nd Place at Kaspersky Labs SecurITCup 2018 in Budapest.

**Netcap** uses Google's Protocol Buffers to encode its output, which allows accessing it across a wide range of programming languages.
Alternatively, output can be emitted as comma separated values (\gls{csv}), which is a common input format for data analysis tools and systems.
The tool is extensible and provides multiple ways of adding support for new protocols, 
while implementing the parsing logic in a memory safe way.
It provides high dimensional data about observed traffic and allows the researcher to focus on experimenting with novel approaches for detecting malicious behavior in network environments,
instead of fiddling with data collection mechanisms and post processing steps.
It has a concurrent design that makes use of multi-core architectures.
The name **Netcap** was chosen to be simple and descriptive.
The command-line tool was designed with usability and readability in mind,
and displays progress when parsing dump files.

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

    $ netcap -in TCP.ncap.gz -select Timestamp,SrcPort,DstPort

Save CSV output to file:

    $ netcap -r TCP.ncap.gz -select Timestamp,SrcPort,DstPort > tcp.csv

Print output separated with tabs:

    $ netcap -r TPC.ncap.gz -tsv

Run with 24 workers and disable gzip compression and buffering:

    $ netcap -workers 24 -buf false -comp false -in traffic.pcapng

Parse pcap and write all data to output directory (will be created if it does not exist):

    $ netcap -r traffic.pcap -out traffic_ncap

Convert timestamps to UTC:

    $ netcap -r TCP.ncap.gz -select Timestamp,SrcPort,Dstport -utc

## Tests

To execute the unit tests, run the followig from the project root:

    go test -v -bench=. ./...

## License

GPLv3