# TODOs

- regenerate nmap database and automate
- port CIP, ENIP and ModbusTCP decoding to stream decoders, add to docs that decodeOpt datagrams must be set

- make database source configurable
- move to home folder on windows?
- db update script
- script installation, add setup check util command 

last CC maxmind geolite2 from 27 Dec 2019 (can be distributed):

- https://web.archive.org/web/20191227182209/http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz
- https://web.archive.org/web/20191227182527/https://geolite.maxmind.com/download/geoip/database/GeoLite2-ASN.tar.gz

- more SMTP transforms
- more DNS transforms / DNSSEC

- add UDP stream decoder support
- flushing of UDP and TCP streams

- drag n drop does not trigger the regex conversion on macOS
- two entities: different value for property - will be combined and the last value for the property will be used?
- to files for content type: remove encodings after ; in graph view
- content types: add ip to label name for content types seen for a specific host VS general

// TODO: connection UIDs
//gommunityid.MakeFlowTuple(
//	netFlow.Src().Raw(),
//	netFlow.Dst().Raw(),
//	binary.BigEndian.Uint16(transportFlow.Src().Raw()),
//	binary.BigEndian.Uint16(transportFlow.Dst().Raw()),
//	1,
//)

- to ports: add services, then the actual ports?
- on ConnectionAuditRecords: GetLongRunningSessions
- add capinfos transform for pcap

- https://github.com/h2non/filetype
- viewlet generation
- open connection in wireshark does not work for live streams, add better error message
- open service type folder for extracted streams

ubuntu move ida to path that maltego will find:
 
    mv idafree-7.0/* ~/.local/bin/

- start capture process: spawn instance in current process to allow cancelling it via maltego UI
- dump config in format from flag pkg and write into separate file

- no need to split logic for pcap and pcapng collection anymore, since ZeroCopyReadPacketData is no longer used (comments: "logic is split for both types here")
- move checkArgs() to utils pkg and use in other cli tools 

- update docs: connection timeouts and flush intervals
- maltego: make showing empty streams configurable, or add a dedicated transform
    - disable processing TCP streams with missing handshake?

- add tests using https://godoc.org/golang.org/x/tools/cmd/stress
- add tests to ensure there are no race bugs

- add option for live capture in maltego: use DPI, append audit records instead of truncating files, set output path as property
- warn about use of ZeroCopyReadPacketData
- For nanosecond resolution use an InactiveHandle for Live capture!    
- add generation code for https://github.com/AliasIO/wappalyzer/blob/master/src/technologies.json
- resolve cmd db categories mapping and add to structures
- add generation code for latest nmap service probes

- add helper function to avoid os.Args[1:] pattern
- GetHostsForGeolocation
- add proper display data for all entities possible (show images and add links etc)
- add transform debug toggle via env var? dump input lt.Values for transform

- to services: show transport protocol first
- add different types for internal or external services 
- add transform that shows only services that transferred data
- Headers + Cookies + Params: add counters to indicate flow volume

- cleanup dbs folder
- add dbs in docker containers

## WIP

## v0.5 Documentation

Install windows compiler toolchain on mac:

    brew install mingw-w64

- Blog: Threat hunting with Netcap and Maltego
- Blog: Metrics with Prometheus and Grafana
- Blog: Framework Introduction and Setup
- Maltego: immediate feedback
- docs: describe custom labeling

- updated contexts
- index generation for vuln search
- live capture with maltego
- refactored decoder constructors, add examples
- document metrics via expvar: https://www.elastic.co/guide/en/beats/metricbeat/current/metricbeat-module-golang.html

### Release

- use new 1.13 strings.ToValidUTF8()
- remove length field from UDP and IPv6
- add issues for hacktoberfest
- update logging for service probe matching
- build an abstraction for merging the chunks in Decode()
- update logging for service probes
- remove colors from pop3 log
- release dashboards

- godoc cleanup
- proxy testing and use simplecert
- count device and ip profiles on stats structure
- document stream decoder implementation

- check source todos
- error handling iteration: improve error messages and reduce panic() usage
- reduce global state iteration
- comment exported symbols iteration
- add constants for logReassemblyError(
- review all log.Fatal and panic usages
- check for usage of fmt.Println(err) / fmt.Println(errClose)

## Issues

- enrich POP3 information if no Mails have been transferred, e.g. capture the command series for fingerprinting
- add audit records for observed protocol buffers
- net dump -stats: show value distribution per field
- implement tls decryption: https://wiki.wireshark.org/TLS
- chart pkts/sec by time or pkt offset in pcap
- add tests for POP3 parsing
- make a nice visual cheat sheet with all audit records and all fields
- create a cli helper to display all fields for a given audit record
- add explanation to each field in the proto definition via tags? could be used to generate docs
- add commandline completion via go package 
- integrate scanning against YARA / suricata rules and add Malware Custom Audit Records
- pcap diff tool

## Frontend Fingerprinting

- use js for identifying frontend frameworks
- use url regexes for identifying frontend frameworks
- use html meta information for identifying frontend frameworks
- use the implies value for enriching the Notes section

## Maltego Plugin

- add To Files for IPProfile, set File host field also for extracted files from pop3
- mark if files extracted from HTTP are a Server Reply or client data sent via GET / POST
- make A general Audit record archive transform: To Summary: Number of Records, Total Size, Fields and Value Distribution
- add transform to do a reverse DNS lookup for \*IP hosts instead of the local lookup

cleanups:

- improve and test content type and executable detection (fix application/gzip) stdlib has exec format header parsers in debug pkg

- Viewlets:
  - Suspicious events:
    - dial to IP directly over HTTP
    - shell commands in http parameters
    - masquerated protocol (by using well known ports for example)
    - http content type does not match content

- To Emails From File: handle common email obfuscation ala: user [at] mail [dot] com
- add transform to scan and analyze a website
- add machine to watch and analyze a website (maybe useful for CTFs or during security assessment?)

entities:

- add different colors for audit record archives?
- handle multiple cpe identifiers for a single service probe
- add file extraction for POP3 emails and attachments

- GetNotWWW (no www.local reverse DNS name?)
- GetUnknownFlows(Filtered) (no http, pop3 flows)

- Create a netcap.Query entity: Add Execute and run the custom query
- link src to dst ports? by creating different entities for src and dst ports?
- improve DisplayInformation to allow tracking updates to an entity over time
- Application: add timestamps when packets have been seen, currently the first seen timestamp for the associated ip profile is repeated

## Protocols / Audit Record Types

- FTP
- Traceroute detection
- Executables
- SOCKS
- SMB
- RDP
- RADIUS
- MySQL
- MongoDB
- Kerberos
- DNP3
- Protobuf
- Syslog
- NetControl
- x509

## Zeekify

- add support for communityID identifiers: https://github.com/satta/gommunityid
- implement the conn.log history field in the same manner as zeek: https://github.com/corelight/bro-cheatsheets/blob/master/Corelight-Bro-Cheatsheets-2.6.pdf
- implement the conn.log conn_state field in the same manner as zeek: https://github.com/corelight/bro-cheatsheets/blob/master/Corelight-Bro-Cheatsheets-2.6.pdf
- add examples for basic data queries similar to: https://old.zeek.org/current/solutions/logs/index.html

## General

- add support to compile only with a subset of features
- PACE2 integration for DPI
- add compile option with dbs compiled into binary

- rapid7 dbs / API integration: https://help.rapid7.com/insightvm/en-us/api/index.html
- implement a net dump summary table like: https://github.com/jbaggs/conn-summary
- httpMetaStore cleanup
- stream protocol identification: add stream signature with patterns for client and server streams 
- move logic to identify protocols from stream banners into dedicated pkg and use ports to improve first guess

- gopacket: add fallback for identifying protocols in tcp and udp payloads
- decodingError: add flow information for debugging
- banner matching: only match the first banner seen for a service?

- reduce init function usage and document the remainders
- reassembly: reduce allocs for ordered stream to 0 again
- add a die(msg string) function and use instead of panic(err), for centralized teardown and cleanup 
- https://github.com/glycerine/offheap

- add comments similar to wireshark info field to records
- add verbose per packet logs via flag (+include packet number)

- scoring / IOC plugin
- net export replay pcap
- implement processing all pcaps in a directory and generate a summary file with stats from all, and aggregate audit records

- net dump: add lag to show conversations and unique ips
- add optional time interval extraction?
- tfRecords output

- implement selective layer decoding with gopacket to improve performance
- add util to dump field and apply post processing: net dump -read UDP.ncap.gz -field Payload | base64 -d

- net dump, add pagination with Enter by default, similar to more? display audit record header in pagination mode?
- capture: add test flag, to emit output for automated tests: #version number \n CSV filename,time,streams,http,pop3,tls,tcp,udp,ethernet,DeviceProfile,software,bytes written,errors
  - collect output and create a table + persist it in tests/logs/test-pcaps-$(date)-$(version).log
  - collect decoding errors from all test pcaps and deduplicate!

- add full stream SMTP parsing
- extract TLS certificates! alert if selfsigned
- integrate CPE database?

- passive DNS: create hosts mapping ala tshark -z hosts -r traffic.pcap
- use JSON decoder from new protobuf release, when gogo integrated the new protobuf V2 API: https://pkg.go.dev/google.golang.org/protobuf/encoding/protojson?tab=doc
- finish net split tool, to split pcap or audit record files by days or hours or by connections similar to $ PcapSplitter -o all_split -f all.pcap -m connection

## Elastic

- create an index for document errors that occurred when pushing data
- create an index for errors that occurred during netcap processing
- automate creation of netcap-* index (add init hook that sets up extra indices and patterns)
- add cli support to reset elastic indices and patterns
- log decoding and reassembly errors into elastic

## Grafana / Prometheus

- instrument the core code with prometheus
- document grafana setup: https://grafana.com/docs/grafana/latest/installation/debian
- document piechart plugin installation:

    grafana-cli plugins install grafana-piechart-panel

## Unit Tests

- CSV: write unit test that checks if the number of fields matches the number of fields produced
- document: script to test different parameters on a single file

- add tests for http audit records and compare results with output from urlsnarf
- unit tests: add tests with non UTF8 strings to check for proto encoding errors

## Resolvers

- integrate to resolvers: https://github.com/fwmark/registry/blob/main/README.md
- add resolvers database update command
- map known RPC numbers? https://github.com/nmap/nmap/blob/master/nmap-rpc
- use official source for OUIs: http://standards-oui.ieee.org/oui/oui.txt
- use ip whitelist for DeviceProfiles
- add Ja3 / ja3s whitelisting

## Bugs / Errors

- ICS pcaps: failed to collect audit records from pcapng file: Unknown magic 73726576

## FAQs

- Is this an IDS?
- Can this handle high throughput

### Tooling

- Audit Record Anonymization for studying sensitive industrial networks

## DPI

- batch DPI calls per flow?
- add support for nDPI 3.2

## net collect

- net collect -gen-keypair ---moveto> net util
- replace AuditRecordHandle in net.collect with netcap.Writer

## net label

- make time zone offset configurable
- print table with stats
- add switch to control uni vs bidirectional labeling?
- display a warning when nothing is there for mapping
- add YARA support for labels
- log number of unmatched alerts
- suricata labeling: switch to intelligence from eve.json

- refactor CheckFields()
- use gopacket.LayerType for c.unknownProtosAtomic and c.allProtosAtomi -> AtomicCounterMap for gopacket.Layers

## Payload Capture

- capture payloads for HTTP?
- add payload data for Flows and Connection if desired
- add flags to enable payload capture for link layer protocols. Currently payload capture only supports some Transport layer protos

## Linux cross compilation

- CC=x86_64-pc-linux-gcc GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -o nc-linux -i github.com/dreadl0ck/netcap/cmd
- GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -o nc-linux -ldflags="-L /usr/local/opt/libpcap/lib" -i github.com/dreadl0ck/netcap/cmd

## Benchmarks

- writing through channels vs mutex
- concatenating Strings Builder vs byte slices etc
- robustness testing / stress test / evasion
- performance assessment + optimizations

## New Protocols

- fix GRE Routing field parsing
- MLDv1MulticastListener + MLDv2MulticastListener
- add support for RMCP protocol
- BGP

## Future Development

- add net grep tool, similar to ngrep
- implement alerting / rule mechanism with separate tool
- transform: add a text based commandline interface for the transformations
- add a -cheatsheet commandline option to each tool, to print command examples into the terminal

- implement reading NC files in rust
- proxy: add support for link layer?
- helper func for ToString() on array?
- performance: allocate fixed size arrays where possible
- events package to define events based on characteristics or IOCs
- implement running a multi instance cluster for packet processing

- flag sort output by timestamp (func in utils)
- flag to limit maximum disk space used in live mode / create a file per day?

- use unique maps for each worker and merge to prevent synced maps?

## Notes

When switching sync.Mutex variables with the deadlock.Mutex variant for debugging,
the following can be used to fix the imports after applying the global find and replace:

    directories=$(go list -f {{.Dir}} ./...)
    test -z "`for dir in $directories; do goimports -w $dir/*.go | tee /dev/stderr; done`"
