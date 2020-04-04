# TODOs

# maltego

- add resolver config to other tools that init a collector
- allow env vars to overwrite flag defaults but not explicitely set ones 
- check TODOs in source
- make file and directory permissions configurable
- add setup and usage documentation, document ENV vars
- net.capture: NETCAP_DATABASE_SOURCE
- net.transform: NETCAP_MALTEGO_OPEN_FILE_CMD
- net.agent: USER
- enable DPI based on env var
- enable DNS lookups based on env var
- pop3 should not depend on HTTP decoder: make stream decoding interface generic
- disable debug timeouts in handlePacket, GetProtocols and AssembleWithContext
- net.capture: log PID on startup
- merge debug modes: -verbose, -debug, -output etc ...
- fix hardcoded version number in dockerfiles
- move Stream type into separate file, rename to Connection to unify wording
- add flag to toggle DNS resolving
- add quiet switch when opening netcap dump files via the Open() call, update transforms
- net.split: split pcap files by days, possibly also hours
- improve and document tests on the ultimate pcap file: https://weberblog.net/the-ultimate-pcap/
- allow tests to execute concurrently 

- Add OpenPacketsInWireshark: For IPAddr, Device, HTTPHost, Flow
- netcap.ServerName -> Add LookupExploits to lookup the service name and version on ExploitDB and others 
- custom icon set for netcap entities

- GetUsers from HTTP BasicAuth + GetPassword
- HTTP parameters: mark if source was GET or POST
- addGetHTTPHeaders
- GetFilesForHTTPHost
- HTTP: which URLs where accessed how often? count in GetHTTPURLs via map?
- HTTP: show GET VS POST? count in GetHTTP* via map?
- Cookies + Params: add counters to indicate flow volume
- Add GetExifData
- add file extraction for POP3 emails and attachments
- add netcap.File entity?
- improve file type detection: detect script languages and executables, use the file extension for first guess 
- netcap.File -> GetMD5

- implement raw streamReader for all other streams to catch reverse shells 
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
- test empty TCP conn over HTTP port (will this lock up the reassembly?)

## General

Reassembly: 2 Options
1) One assembler per worker + 1 shared connection pool (currently implemented)
2) One global assembler per protocol with a dedicated stream pool for that protocol (reduces lock contention)

- add tests for http audit records and compare results with output from urlsnarf
- add constants in maltego pkg for netcap entity names
- implement passive dns hosts mapping generation in netcap
- check if order of values in maltego list matches the expectation
- broadcast address: mark as part of the internal network?
- Application: add timestamps when packets have been seen, currently the first seen timestamp for the asscociated ip profile is repeated
- add tests for POP3
- constconf: generate a configuration with constant values -> compiler can optimize better

- batch DPI calls per flow? 
- use nDPI 3.2

- flag.FlagSet instead of cobra for sub commands?
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
