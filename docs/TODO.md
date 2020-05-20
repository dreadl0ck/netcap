# TODOs

- Maltego integration
- add full stream SMTP parsing
- add lookups for DHCP Fingerprints

- make using local vs reverse dns lookups configurable for service audit records
- passive DNS: create hosts mapping ala tshark -z hosts -r traffic.pcap

- add field to service if internal or external
- add filter flag to only include internal services
- add flag to exclude services that transferred no data

- make a group extraction util and expand all groups in all strings properly
- add keyword filter and compile as regex? username, password etc might appear somewhere in stream contents, e.g inside HTML etc
- extract TLS certificates! alert if selfsigned

- update reassembly unit tests
- map known RPC numbers? https://github.com/nmap/nmap/blob/master/nmap-rpc
- net dump, add pagination with Enter by default, similar to more? display audit record header in pagination mode?
 
- capture: add test flag, to emit output: #version number \n CSV filename,time,streams,http,pop3,tls,tcp,udp,ethernet,DeviceProfile,software,bytes written,errors
    -> collect output and create a table + persist it in tests/logs/test-pcaps-$(date)-$(version).log 
    -> collect decoding errors from all test pcaps and deduplicate!
    
## v0.5 Documentation

- Blog: Threat hunting with Netcap and Maltego
- Blog: Metrics with Prometheus and Grafana
- Blog: Framework Introduction

## Maltego Plugin

- Add OpenPacketsInWireshark: For IPAddr, Device, HTTPHost, Flow
- netcap.ServerName -> Add LookupExploits to lookup the service name and version on ExploitDB and others
- custom icon set for netcap entities
- make snaplen configurable for GetDeviceProfiles
- add live capture with maltego?
- GetUsers from HTTP BasicAuth + GetPassword
- HTTP parameters: mark if source was GET or POST
- addGetHTTPHeaders
- GetFilesForHTTPHost
- HTTP: which URLs where accessed how often? count in GetHTTPURLs via map?
- HTTP: show GET VS POST? count in GetHTTP\* via map?
- Cookies + Params: add counters to indicate flow volume
- Add GetExifData
- add file extraction for POP3 emails and attachments
- add netcap.File entity?
- improve file type detection: detect script languages and executables, use the file extension for first guess
- netcap.File -> GetMD5
- TLS fingerprints: GetJa3? for IPAddr entities
- GetLongRunningSessions

- text file types: add GetLinks and GetEmails, GetPhonenumbers etc
- GetNotWWW (no www.local reverse DNS name?)
- GetUnknownFlows(Filtered) (no http, pop3 flows)
- GetHostsForGeolocation
- GetApplicationsForCategory is broken

- Create a netcap.Query entity: Add Execute and run the custom query
- link src to dst ports?
- improve DisplayInformation to allow tracking updates to an entity over time
- define triggers to highlight suspicious links in red
- MIME type: check if executables are properly detected
- check if order of values in maltego list matches the timestamps
- Application: add timestamps when packets have been seen, currently the first seen timestamp for the associated ip profile is repeated

## General

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
