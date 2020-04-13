# TODOs

## v0.5 Documentation

- document configuration via environment or file
- document tests on the ultimate pcap file: https://weberblog.net/the-ultimate-pcap/
- custom labeling
- new protocols
- JA3s
- update usage examples for new syntax
- godoc cleanup
- regenerate cheatsheets
- set num workers to num cores by default
- mark unknown protos with * and add it as legend below output
- update proxy docs: -proxy flag changed to -proxy-config
- document config file feature + gen-config

## TODOs

- record new asciicasts

## Maltego Plugin

- Add OpenPacketsInWireshark: For IPAddr, Device, HTTPHost, Flow
- netcap.ServerName -> Add LookupExploits to lookup the service name and version on ExploitDB and others
- custom icon set for netcap entities

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
- Application: add timestamps when packets have been seen, currently the first seen timestamp for the asscociated ip profile is repeated

## General

- capture unknown L7 protocol TCP streams and write to disk
- net.split: split pcap or audit record files by days or hours
- check TODOs in source
- improve tests
- add tests for POP3 parsing
- add tests for http audit records and compare results with output from urlsnarf
- implement passive dns hosts mapping generation in netcap
- sort errors by the number of occurrences (COUNT) for print and log in errors.log
- add log flag to enable writing output to file netcap.log and stdout simultaneously
- use a logger without reflection for performance: zap?
- add a -cheatsheet commandline option to each tool, to print command examples into the terminal
- integrate new TLS layer from gopacket
- use ip whitelist for DeviceProfiles

Reassembly: 2 Options

1. One assembler per worker + 1 shared connection pool (currently implemented)
2. One global assembler per protocol with a dedicated stream pool for that protocol (reduces lock contention)

- constconf: generate a configuration with constant values -> compiler can optimize better

- batch DPI calls per flow?
- use nDPI 3.2

- label tool: display a warning when nothing is there for mapping
- use new 1.13 strings.ToValidUTF8()

- remove length field from UDP and IPv6
- net.collect -gen-keypair -> net.util
- replace AuditRecordHandle in net.collect with netcap.Writer
- colorize tool output
- add YARA support for labels

- add contributions welcome to README
- shortly describe main framework components in README (cmd/\*)

- add ROADMAP
- BLOG: Setup Guide
- Visualize CIC datasets

- implement reading NC files in rust
- Full Proxy?

- capture payloads for HTTP
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

## Sensor

- client reuse conn?
- implement data export to elastic stack / influx

## New Protocols

- fix GRE Routing field parsing
- MLDv1MulticastListener + MLDv2MulticastListener

## Future Development

- helper func for ToString() on array?
- add github wiki
- godoc API cleanup
- handle panic(err) gracefully
- performance: allocate fixed size arrays when encoding
- add flag to map field values to constant names
- add test files for different protocols
- JSON output
- events package to define events based on characteristics or IOCs
- scale to multi instance architecture
- data exporters + visualization dashboards / VR etc
- robustness testing / pentest
- performance assessment + optimizations

- labeling: how many unmatched alerts?
- labeling: switch to intelligence from eve.json

- display custom encoder stats in final view: add stats func to custom encoder and call them on destroy
- TCP stream reassembly: make App Layer decoding configurable, to allow extension for other layer 7 protos (SMTP, FTP etc)
- flag sort output by timestamp (func in utils)
- flag to limit maximum disk space used in live mode / create a file per day?
- add go commandline completion lib
- port the dataframe encoding logic to Go
- make labeling work on bare CSV based on timestamp + plus source pcap
- also dump http uploads via POST
- pprof & memprof tests
- use unique maps for each worker and merge to prevent synced maps?
- integrate HASSH
- netcap plugins?
- integrate labeling function for YARA
- go-dpi classifiers?
