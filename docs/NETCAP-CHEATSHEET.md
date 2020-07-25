# NETCAP Cheatsheet

> Documentation: [docs.netcap.io](https://docs.netcap.io)

|Command|Description|
|-------|-----------|
|net capture -iface eth0 | Read traffic live from interface, stop with _Ctrl-C_ \(_SIGINT_\) |
|net capture -readead traffic.pcap | Read traffic from a dump file \(supports PCAP or PCAPNG\) |
|net capture -iface en0 -bpf "host 192.168.1.1"|apply a BPF when capturing traffic live|
|net capture -read traffic.pcap -bpf "host 192.168.1.1"|apply a BPF when parsing a dumpfile|
|net capture -read traffic.pcap -include Ethernet,Dot1Q,IPv4,IPv6,TCP,UDP,DNS|Include specific decoders (only those named will be used)|
|net capture -read traffic.pcap -exclude TCP,UDP|Exclude decoders (this will prevent decoding of layers encapsulated by the excluded ones)|
|net capture -workers 24 -buf false -comp false -read traffic.pcapng|Run with 24 workers and disable gzip compression and buffering|
|net capture -read traffic.pcap -out traffic_ncap|Parse pcap and write all data to output directory \(will be created if it does not exist\)|
|net dump -read TCP.ncap.gz|Read a netcap dumpfile and print to stdout as CSV|
|net dump -fields -read TCP.ncap.gz|Show the available fields for a specific Netcap dump file|
|net dump -read TCP.ncap.gz -select Timestamp,SrcPort,DstPort|Print only selected fields and output as CSV|
|net dump -read TCP.ncap.gz -select Timestamp,SrcPort,DstPort > tcp.csv|Save CSV output to file|
|net dump -read TPC.ncap.gz -tsv|Print output separated with tabs|
|net dump -read TCP.ncap.gz -select Timestamp,SrcPort,Dstport -utc|Convert timestamps to UTC|
|net dump -read TCP.ncap.gz -header|Show audit record header|
|net dump -read TCP.ncap.gz -struc|Print structured audit records|
|net dump -read TCP.ncap.gz -tsv|Print audit records as Tab Separated Values|
|net dump -read UDP.ncap.gz -table |Print as table|
|net dump -read TCP.ncap.gz -sep ";"|Print audit records with Custom Separator|
|net dump -read TCP.ncap.gz -check|Check if generated output contains the correct number of separator symbols|
|net dump -read UDP.ncap.gz -fields|Show available fields for the audit record type|
|net collect -gen-keypair|generate keypair for distributed collection and write to disk|
|net collect -privkey priv.key -addr 127.0.0.1:4200|start collection server|
|net agent -pubkey pub.key -addr 127.0.0.1:4200|start a sensor agent for exporting data|
