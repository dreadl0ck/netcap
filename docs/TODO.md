# TODOs

# maltego

- add tests for POP3
- add file extraction for POP3 emails and attachments
- set attachments on mail audit record type
- add mail header fields to maltego entity 

- Email: GetAttachments
- GetDHCP for device identification
- GetUsers from POP3 / BasicAuth etc
- text Content types: add GetLinks and GetEmails
- HTTP: GetHTTPHost -> GetURLs
- HTTP: GetHTTPHost -> GetParameters
- HTTP: GetHTTPHost -> GetCookies
- add GetHTTPContentTypes -> GetFiles
- DPI: GetApplicationCategories -> GetApplications?
- add GetMails / GetMailContacts

- attach files (preview?) and open them by click
- link src to dst ports?
- update DisplayInformation to allow tracking updates to an entity over time
- define triggers to highlight links in red
- MIME type: check if executables are properly detected
- destination ips: queries for audit records must use DstIP == ipaddr !

## General

- finish types implementation for POP3
- remove DNS logic from stream reassembly
- move Stream type into separate file, rename to Connection to unify wording
- add flag to toggle DNS resolving
- add quiet switch when opening netcap dump files via the Open() call, update transforms
- create profiles for Link Layer only devices as well
- http: basic auth extraction from URL: GetHTTPBasicAuth?
 
- single binary as plugin / framework
- use nDPI 3.2 and libprotoident latest version
- test on the ultimate pcap file

- flag.FlagSet instead of cobra for sub commands?
- net.split: split pcap files by days, possibly also hours
- label tool: display a warning when nothing is there for mapping
- use new 1.13 strings.ToValidUTF8()

- remove length field from UDP and IPv6
- net.collect -gen-keypair  -> net.util
- replace AuditRecordHandle in net.collect with netcap.Writer
- colorize tool output

- check TODOs in source code
- add YARA support for labels

- add contributions welcome to README
- shortly describe main framework components in README (cmd/*)

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
