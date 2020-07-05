# TODOs

maltego cleanups:
- maltego: AddEntity wrapper that always adds path property field?
- maltego: add transform debug toggle via env var? dump input lt.Values for transform 
- maltego: add constants for netcap types for AddEntity()
- add constants for ent.SetLinkDirection("output-to-input")
- add constants for hex colors: ent.SetLinkColor("#000000")
- remove setting path attribute on entities to the path of the DeviceProfiles for all types + document

- improve and test content type and executable detection (fix application/gzip)
- include machines into generated config archive
- live capture: give proper error when interface name is not present or wrong
- ensure using Service and software audit records work also when not all DBs are available
- add Show All Services transform: show both TCP and UDP
    - add different types for internal or external services
        - add Show Services without Data Exchange to include services that transferred no data and exlcude those by default?
- update reassembly unit tests
- Add OpenPacketsInWireshark: For IPAddr, Device, HTTPHost, Flow
- make snaplen configurable: add as property to netcap.PCAP, default 1514
- addGetHTTPHeaders
- GetFilesForHTTPHost
- Cookies + Params: add counters to indicate flow volume
- Add GetExifData
- improve file type detection: detect script languages and executables, use the file extension for first guess
- TLS fingerprints: GetJa3? for IPAddr entities
- MIME type: check if executables are properly detected

wireshark pcap downloads: wget -r -np -l 1 -A pcap https://www.wireshark.org/download/automated/captures/

on audit record archives:
- on TLSHellos: To JA3 Fingerprints
- on TCP/UDP: To Hosts, To Ports, To Streams
- on POP3: To Mail Users
- on IP: To Source IPs, To Destination IPs
- on Ethernet: To Hardware Addresses
- on ARP: To Hardware Addresses
- on Connection: To Connections (src <-> dst format=?), To Connections with highest data transfer, To Connections with lowest data transfer, To IANA Services
- on DHCPv6: To Devices
- on HTTP: To HTTP Clients, To HTTP Content Types, To HTTP URLs
- on netcap.Website: To Website Visitors, To Website Parameters, To Website Cookies
- on Connections: GetLongRunningSessions

## v0.5 Documentation

- Blog: Threat hunting with Netcap and Maltego
- Blog: Metrics with Prometheus and Grafana
- Blog: Framework Introduction and Setup
- index generation
- live capture with maltego
- refactored encoder constructors

## Maltego Plugin

- Viewlets:
    - Suspicious events:
        - dial to IP directly
        - shell commands in http parameters
        - masquerated protocol (by using well known ports for example)
        - http content type does not match content

- integrate scanning against YARA / suricata rules and add Malware Custom Audit Records
- add a transform to open executable files for analysis, set tool via env var
- make general Audit record archive transform: To Summary: Number of Records, Total Size, Fields and Value Distribution

- add transform to do a reverse DNS lookup for *IP hosts instead of the local lookup

entities:
- add different colors for Internal and External IPs: or merge them? Also rename device ip to source ip and contact ip to destination ip
- add different colors for audit record archives?
- handle multiple cpe identifiers for a single service probe

- add file extraction for POP3 emails and attachments

- GetNotWWW (no www.local reverse DNS name?)
- GetUnknownFlows(Filtered) (no http, pop3 flows)
- GetHostsForGeolocation
- GetApplicationsForCategory is broken

- Create a netcap.Query entity: Add Execute and run the custom query
- link src to dst ports?
- improve DisplayInformation to allow tracking updates to an entity over time

- check if order of values in maltego list matches the timestamps
- Application: add timestamps when packets have been seen, currently the first seen timestamp for the associated ip profile is repeated

## General

- net dump, add pagination with Enter by default, similar to more? display audit record header in pagination mode? 
- capture: add test flag, to emit output for automated tests: #version number \n CSV filename,time,streams,http,pop3,tls,tcp,udp,ethernet,DeviceProfile,software,bytes written,errors
    - collect output and create a table + persist it in tests/logs/test-pcaps-$(date)-$(version).log 
    - collect decoding errors from all test pcaps and deduplicate!
- add database update command
- add full stream SMTP parsing
- extract TLS certificates! alert if selfsigned
- map known RPC numbers? https://github.com/nmap/nmap/blob/master/nmap-rpc
- integrate CPE database?
- parse cpes, for example with https://github.com/knqyf263/go-cpe
- passive DNS: create hosts mapping ala tshark -z hosts -r traffic.pcap
- use JSON encoder from new protobuf release, when gogo integrated the new protobuf V2 API: https://pkg.go.dev/google.golang.org/protobuf/encoding/protojson?tab=doc
- monitor repo with LGTM
- implement the connection history string in the same manner as zeek
- official source for OUIs: http://standards-oui.ieee.org/oui/oui.txt 
- net split tool: add support to split pcaps into connections, like: $ mkdir all_split && dreadbook:test alien$ PcapSplitter -o all_split -f all.pcap -m connection
- ICS pcaps: failed to collect audit records from pcapng file: Unknown magic 73726576
- add net grep tool, similar to ngrep
- check TODOs in source
- add support for RMCP protocol
- implement alerting / rule mechanism with separate tool
- remove global state in encoder and collector pkgs?
- transform: add a text based commandline interface for the transformations
- capture unknown L7 protocol TCP streams and write to disk
- new tool: net split, to split pcap or audit record files by days or hours
- implement passive dns hosts mapping generation in netcap
- sort errors by the number of occurrences (COUNT) for print and log in errors.log
- add log flag to enable writing output to file netcap.log and stdout simultaneously
- use a logger without reflection for performance: zap?
- add a -cheatsheet commandline option to each tool, to print command examples into the terminal
- integrate new TLS layer from gopacket
- use ip whitelist for DeviceProfiles
- implement a JSON output writer?
- integrate: https://ja3er.com/downloads.html
- add Ja3 / ja3s whitelisting
- use new 1.13 strings.ToValidUTF8()
- remove length field from UDP and IPv6
- constconf: generate a configuration with constant values -> compiler can optimize better

## tests

- add tests for POP3 parsing
- add tests for http audit records and compare results with output from urlsnarf

## Reassembly
 
2 Options:

1. One assembler per worker + 1 shared connection pool (currently implemented)
2. One global assembler per protocol with a dedicated stream pool for that protocol (reduces lock contention)

## DPI

- batch DPI calls per flow?
- add support for nDPI 3.2

## net collect

- net.collect -gen-keypair -> net.util
- replace AuditRecordHandle in net.collect with netcap.Writer

## net label

- label tool: display a warning when nothing is there for mapping
- add YARA support for labels
- docs: describe custom labeling 

- Visualize CIC datasets
- implement reading NC files in rust
- proxy: add support for link layer? 

- capture payloads for HTTP?
- add payload data for Flows and Connection if desired
- add flags to enable payload capture for link layer protocols. Currently payload capture only supports some Transport layer protos

- refactor printProgress()
- refactor CheckFields()
- use gopacket.LayerType for c.unknownProtosAtomic and c.allProtosAtomi -> AtomicCounterMap for gopacket.Layers

## Linux cross compilation

- CC=x86_64-pc-linux-gcc GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -o nc-linux -i github.com/dreadl0ck/netcap/cmd
- GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -o nc-linux -ldflags="-L /usr/local/opt/libpcap/lib" -i github.com/dreadl0ck/netcap/cmd

## Benchmarks

- writing through channels vs mutex
- concatenating Strings Builder vs byte slices etc
- robustness testing / stress test / evasion
- performance assessment + optimizations
- pprof & memprof tests

## Sensor

- client reuse conn?
- implement data export to elastic stack / influx

## New Protocols

- fix GRE Routing field parsing
- MLDv1MulticastListener + MLDv2MulticastListener

## Future Development

- colorize tool output for better readability
- helper func for ToString() on array?
- check for panic(err) instances and handle more gracefully
- performance: allocate fixed size arrays when encoding
- events package to define events based on characteristics or IOCs
- scale to multi instance architecture

- labeling: log number of unmatched alerts
- suricata labeling: switch to intelligence from eve.json
- TCP stream reassembly: ease adding support for other stream based protocols
- flag sort output by timestamp (func in utils)
- flag to limit maximum disk space used in live mode / create a file per day?

- use unique maps for each worker and merge to prevent synced maps?
- integrate HASSH SSH fingerprinting
- netcap go plugins?

## Notes

When switching sync.Mutex variables with the deadlock.Mutex variant for debugging,
the following can be used to fix the imports after applying the global find and replace:

    directories=$(go list -f {{.Dir}} ./...)
    test -z "`for dir in $directories; do goimports -w $dir/*.go | tee /dev/stderr; done`" 