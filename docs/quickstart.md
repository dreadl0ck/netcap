---
description: For those who can't wait to get their hands dirty.
---

# Quickstart

## Capture traffic to create audit records

Read traffic live from interface, stop with _Ctrl-C_ \(_SIGINT_\):

```text
$ net capture -iface eth0
```

Read traffic from a dump file \(supports PCAP or PCAPNG\):

```text
$ net capture -read traffic.pcap
```

## Read audit records

Read a netcap dumpfile and print to stdout as CSV:

```text
$ net dump -read TCP.ncap.gz
```

Show the available fields for a specific Netcap dump file:

```text
$ net dump -fields -read TCP.ncap.gz
```

Print only selected fields and output as CSV:

```text
$ net dump -read TCP.ncap.gz -select Timestamp,SrcPort,DstPort
```

Save CSV output to file:

```text
$ net dump -read TCP.ncap.gz -select Timestamp,SrcPort,DstPort > tcp.csv
```

Print output separated with tabs:

```text
$ net dump -read TPC.ncap.gz -tsv
```

Run with 24 workers and disable gzip compression and buffering:

```text
$ net capture -workers 24 -buf false -comp false -read traffic.pcapng
```

Parse pcap and write all data to output directory \(will be created if it does not exist\):

```text
$ net capture -read traffic.pcap -out traffic_ncap
```

Convert timestamps to UTC:

```text
$ net dump -read TCP.ncap.gz -select Timestamp,SrcPort,Dstport -utc
```

## Show Audit Record File Header

To display the header of the supplied audit record file, the -header flag can be used:

```text
$ net capture -read TCP.ncap.gz -header

+----------+---------------------------------------+
|  Field   |                Value                  |
+----------+---------------------------------------+
| Created  | 2018-11-15 04:42:22.411785 +0000 UTC  |
| Source   | Wednesday-WorkingHours.pcap           |
| Version  | v0.3.3                                |
| Type     | NC_TCP                                |
+----------+---------------------------------------+
```

## Print Structured Audit Records

Audit records can be printed structured, this makes use of the _proto.MarshalTextString\(\)_ function. This is sometimes useful for debugging, but very verbose.

```text
$ net dump -read TCP.ncap.gz -struc
...
NC_TCP
Timestamp: "1499255023.848884"
SrcPort: 80
DstPort: 49472
SeqNum: 1959843981
AckNum: 3666268230
DataOffset: 5
ACK: true
Window: 1025
Checksum: 2348
PayloadEntropy: 7.836586993143013
PayloadSize: 1460
...
```

## Print as CSV

This is the default behavior. First line contains all field names.

```text
$ net dump -read TCP.ncap.gz
Timestamp,SrcPort,DstPort,SeqNum,AckNum,DataOffset,FIN,SYN,RST,PSH,ACK,URG,...
1499254962.234259,443,49461,1185870107,2940396492,5,false,false,false,true,true,false,...
1499254962.282063,49461,443,2940396492,1185870976,5,false,false,false,false,true,false,...
...
```

## Print as Tab Separated Values

To use a tab as separator, the _-tsv_ flag can be supplied:

```text
$ net dump -read TCP.ncap.gz -tsv
Timestamp               SrcPort DstPort Length  Checksum PayloadEntropy  PayloadSize
1499254962.084372       49792   1900    145     34831    5.19616448      137
1499254962.084377       49792   1900    145     34831    5.19616448      137
1499254962.084378       49792   1900    145     34831    5.19616448      137
1499254962.084379       49792   1900    145     34831    5.19616448      137
...
```

## Print as Table

The _-table_ flag can be used to print output as a table. Every 100 entries the table is printed to stdout.

```text
$ net dump -read UDP.ncap.gz -table -select Timestamp,SrcPort,DstPort,Length,Checksum
+--------------------+----------+----------+---------+-----------+
|     Timestamp      | SrcPort  | DstPort  | Length  | Checksum  |
+--------------------+----------+----------+---------+-----------+
| 1499255691.722212  | 62109    | 53       | 43      | 38025     |
| 1499255691.722216  | 62109    | 53       | 43      | 38025     |
| 1499255691.722363  | 53       | 62109    | 59      | 37492     |
| 1499255691.722366  | 53       | 62109    | 59      | 37492     |
| 1499255691.723146  | 56977    | 53       | 43      | 7337      |
| 1499255691.723149  | 56977    | 53       | 43      | 7337      |
| 1499255691.723283  | 53       | 56977    | 59      | 6804      |
| 1499255691.723286  | 53       | 56977    | 59      | 6804      |
| 1499255691.723531  | 63427    | 53       | 43      | 17441     |
| 1499255691.723534  | 63427    | 53       | 43      | 17441     |
| 1499255691.723682  | 53       | 63427    | 87      | 14671     |
...
```

## Print with Custom Separator

Output can also be generated with a custom separator:

```text
$ net dump -read TCP.ncap.gz -sep ";"
Timestamp;SrcPort;DstPort;Length;Checksum;PayloadEntropy;PayloadSize
1499254962.084372;49792;1900;145;34831;5.19616448;137
1499254962.084377;49792;1900;145;34831;5.19616448;137
1499254962.084378;49792;1900;145;34831;5.19616448;137
...
```

## Validate generated CSV output

To ensure values in the generated CSV would not contain the separator string, the _-check_ flag can be used.

This will determine the expected number of separators for the audit record type, and print all lines to stdout that do not have the expected number of separator symbols. The separator symbol will be colored red with ansi escape sequences and each line is followed by the number of separators in red color.

The _-sep_ flag can be used to specify a custom separator.

```text
$ net util -read TCP.ncap.gz -check
$ net util -read TCP.ncap.gz -check -sep=";"
```

