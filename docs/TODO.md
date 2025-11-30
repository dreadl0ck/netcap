# TODOs

- NONSTANDARD_HTTP is gold info from dpi fire alert
- Remove import path prefixes for compiled binaries to reduce size and obscure build path
- Connections page: arrow up and down should change current file up and down when viewing a conversation 
- RADIUS and UPnP credential extraction review 
- Files page: only show the file name in the table and truncate the connection ident string, only show full filename in detail view. Also truncate the file name if it exceeds 50 chars.
- Fingerprints table: the fingerprint hash should not line wrap. Prevent wrap and slightly decrease font size on smaller screens.
- Credentials page: truncate usernames and passwords after 25 chars in the table, and colorise the Flow ident in the table view the same way as on connections page.
- Connection detail view: add show secrets button, if a credential for that connection exists. Open the credentials page and filter for the flow ident.
- Rename credentials to secrets
- GRE audit records contain too little info to be useful. Improve.
- failed to write proto: error encoding proto: proto: field "types.File.Source" contains invalid UTF-8
- Extend File audit records with a field for the protocol name it was extracted from and show the info on Files page table and allow to filter for it.

- webUI View records: Showing very large record types eg DeviceProfile, even a single profile could be too big to display. Truncate max output in backend to 2000 characters. 

- TLS connections show SNIs not as credentials
- Command to show capinfos for PCAP also in webUI

- Files audit records: hash file content and only save each content once, eg html files in arp-dns all 404 dupes
- Connections dont load sometimes, debug

- integrate magika and invoke on files folder after extraction (github.com/google/magika/tree/main/go)

- Analysis session format, storing and loading

- failed to download databases: failed to fetch database metadata: server returned status 500 Internal Server Error for https://dbs.netcap.io/dbs/latest: Metadata not found
- configure fingerbank lookups and caching

- make it configurable per harvester if it runs only for the default port or for all streams. for some harvester it makes sense to runs them against all plaintext protos.
- data mining on plaintext connection data: extract URLs, what looks like secrets, ctf flags etc

- support to enable / disable individual service probes. regenerate the probe list with commented out if disabled.
- support creating service probes on the services page service details: add create probe button, switch to probes page, open create modal and insert service banner 

- software audit records: remove Vendor Field and use only Product? if Product info is empty, write the info we would have written into Vendor before as a fallback, or combine the two fields.
- fix capture and inspect local results
- auto extract information from robots.txt and content security policy and use it to enrich audit records
- records: rename Download All to Download Records + new Download CSV button to convert and download all records as CSV files (caution with gzip compression middleware causing issues again)

- dashboards feature: save and load dashboards, made of different charts. create a simple UI to rearrange charts and choose the audit record type, field and type of chart for each.
- dev mode: enable debugging with https://nextjs.org/docs/app/guides/mcp

- integrate gohs with vectorscan on mac

----

Later

- test suite using tshark and a set of pcaps 
- EthernetCTP / LinkLayerDiscovery / others - Group audit record types into one per protocol?
- VSCode plugin to open pcaps with netcap and render the webUI in tab for analysis of the loaded PCAP file

----

Charts

- echarts v6 currently used only for pie chart on Files page. Add more charts using v6 (https://echarts.apache.org/en/index.html)
- Geolocation chart with ingress / egress based coloring switch
- Table with PCAPs and number of audit records of each type, sortable ("eg: which capture file had the most Credentials")
- DHCP fingerprinting results for DeviceProfile and IPProfile

- overview: standard VS non standard ports in use for services
- Visualize Applications (Clustering)
- Sankey Diagram for Flows between IPs
- Sankey Diagram for Flows between Devices
- treemap explorer: click audit record type, choose field, see all values

----

DBs

- update dbs
  - dbs: TorDB (torlookup) databases
    - https://www.dan.me.uk/tornodes
    - https://github.com/alireza-rezaee/tor-nodes?tab=readme-ov-file
- add custom data support for dbs and integrate it in UI
- ip and domain reputation
  - domain age: mark domains registered in the past 30 days
  - categorize domains (sector etc)
  - integrate feeds from https://threatview.io
- add config to apply extra asset info to audit records: eg employee workstations in internal network etc
- resolver API: add ip blacklist and integrate feeds
- resolvers: integrate IP and domain reputation feeds

----

New features:

- switch to corelight community id spec: (https://github.com/corelight/community-id-spec) for the Connection UIDs

- mimicry rule: alert if traffic on standard port does not match the expected protocol (using DPI results)
- Connections VS Conversations (= all Connections between two hosts) Abstraction

- compression for /api/chart/data - Chart data endpoints - currently disabled 
- compression for downloading ALL files and pcaps currently disabled

- model more security rules on top of HTTP
- model more security rules on top of DNS

- Audit records data duplications: IPProfile Ja3Hashes, Alerts

- audit records filter help box: make suggestions context specific for the current audit record type and data with configurable inputs as template, load a couple audit records to obtain real values and populate the template for help text with real values
- add guide how to add new protocol support and show example commit

- add some test for stream reassembly that are run with -count flag to ensure number and properties of reassembled streams are consistent

- docs iteration
- tests iteration

- update engine: rules / filters need to be executed in batches so that large amounts of data can be processed.

- add rules to alert on the presence of certain audit record types, eg Credentials, Vulns, Exploits etc
- implement bug reporting in local mode

- add detailed field descriptions for each protocol and show in explore view when selecting a field

- netcap core should produce info which fields contain data for the audit records, so that UI can use this only show fields that make sense for filtering, without having to parse the entire data again.

- try-service: crash reporting mechanism: when the service panics and crashes, we need the full service log, and all netcap logfiles copied and archived together with the input pcap file for reproduction. An alert should be fired via email. add support to connect an SMTP service to send alert emails to an administrator.

- enriching audit records should be two stage process? parse minimal info in first step and everything that can be derived later in a second step

- switch to gopacket/reassembly and tcpassembly? implement tests to verify the decoded streams are consistent in between executions

- decoders page: clean up list and mapping
  - document: stateful VS stateless packet decoders (eg UDP vs Connection)

-----

  for f in *.pcap *.pcapng; do [ -f "$f" ] && net capture -y -read "$f" -out "${f%.*}"; done

with break on interrupt:

  for f in *.pcap *.pcapng; do [ -f "$f" ] && { net capture -read "$f" -out "${f%.*}" || break; }; done

or with trap:

  trap 'exit 130' INT; for f in *.pcap *.pcapng; do [ -f "$f" ] && net capture -read "$f" -out "${f%.*}"; done

or

  find . -maxdepth 1 \( -name "*.pcap" -o -name "*.pcapng" \) -type f -exec sh -c 'net capture -read "$1" -out "${1%.*}"' _ {} \;


----

PCAPs for test suite:
- check out wireshark / suricata test pcap suite.
- scrape all files from https://www.malware-traffic-analysis.net/training-exercises.html
- https://github.com/pevma/mrp
- https://github.com/brett-fitz/malware-pcap
- https://github.com/ntop/nDPI/tree/dev/tests/cfgs/default/pcap
- https://wiki.wireshark.org/samplecaptures
- https://github.com/wireshark/wireshark/tree/master/test/captures
- https://github.com/OISF/suricata-verify
- https://wiki.wireshark.org/uploads/2b93239dd0d98241e2173b78a91163b8/The-Ultimate-PCAP.7z
- https://weberblog.net/tag/pcap/
- https://www.chappell-university.com/post/check-out-the-ultimate-pcapng
- https://www.netresec.com/?page=PcapFiles

Integration Tests as github action:

1) artifact

You can store the .pcap files (or compressed bundles of them) as artifacts attached to a previous workflow.
Then, your test workflow can download them when it runs.

Example:

Upload job (run once manually):

```
name: Upload PCAP dataset
on:
  workflow_dispatch:

jobs:
  upload:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Upload PCAPs
        uses: actions/upload-artifact@v4
        with:
          name: test-pcaps
          path: testdata/pcaps/
```          

test workflow

```
name: Run Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Download PCAP dataset
        uses: actions/download-artifact@v4
        with:
          name: test-pcaps
          path: ./testdata/pcaps
      - name: Run tests
        run: pytest
```

This works perfectly for datasets ≤5 GB total and ≤2 GB per file.
Artifacts last up to 90 days by default (you can set a shorter retention if needed).

2) download

name: Download test dataset
  run: |
    mkdir testdata/pcaps
    curl -L https://example.com/pcaps/testset.tar.gz -o testset.tar.gz
    tar -xzvf testset.tar.gz -C testdata/pcaps

You can download files up to ~20–25 GB safely on a GitHub-hosted runner.

----

https://github.com/florianl/go-nflog

- http host session duration:
  - how much time did a user spent on a specific host?
    - eg measure as duration between first and last http request to a host



- add dpi / nodpi arm64 builds for linux

- extend api with context to allow stopping collector

## NEXT

- create elastic indices: netcap-ospf does already exist?
- censor passwords from dumped config in netcap.log
- log hint to use pcapfix tool for errors during pcap processing like 'capture length exceeds snap length'

- overwrite check does not include other formats than ncap or ncap.gz

- add flag to disable writing files to disk (but: still generating the audit records)
- unify flag naming and update docs, eg fileStorage is camel case

## BACKLOG
  
- add an audit record file log rotation and cleanup mechanism
- log amount of bytes written to disk for files and conns when exiting the cli tool

- add option to preserve raw pcap when capturing interface, for live capture in maltego
- maltego: document that drag and drop via Codium works on macOS and Linux!
- Open traffic with credentials in Wireshark
- on exploit entity: Open Traffic for Exploit in Wireshark

- add configurable timeout for processing of last TCP / UDP streams
- add option to stop processing streams after X bytes?

- restrict reassembly from growing unbounded when reading from pcap (+ how to handle it in live mode)

Add tool to download latest geolite dbs:

https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=YOUR_LICENSE_KEY&suffix=tar.gz
https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=YOUR_LICENSE_KEY&suffix=tar.gz
https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOUR_LICENSE_KEY&suffix=tar.gz

- set all link types

- https://github.com/fyne-io/fyne
- https://github.com/blushft/go-diagrams
- https://github.com/thomasp11/tcp-reassembly
- https://github.com/0x4D31/quick 
- https://github.com/TylerBrock/colorjson
- https://bytefield-svg.deepsymmetry.org/bytefield-svg/1.5.0/intro.html

- Connection: preserve how many bytes each party sent and who initiated the connection
- Connection: use communityIDs

- add option to enrich the audit records with db information as a post processing step
  
- add custom netcap additions to service probes, manage in separate file
- add compilation timestamp to logs for debugging
- parallelize decoder init

- generic IP / Host blacklist / whitelist
- integrate teler resources

- connection flushing
- flushing of UDP and TCP streams

- decoders: make fields private?
    
    // used to keep track of the number of generated audit records
    NumRecordsWritten int64

    // Writer for audit records
    Writer netio.AuditRecordWriter

- decoders: refactor singleton pattern and provide an initializer function instead?
- stream decoders: add zap logger to decoder structure?
- register decoder during creation?

- refactor pkg structure?
    - packet.NewDecoder(...)
    - stream.NewDecoder(...)
    - decoder.InitStreamDecoders()
    - decoder.InitPacketDecoders()
    
- integrate https://github.com/kitabisa/teler-resources

- more SMTP transforms
- more DNS transforms / DNSSEC
- add intel hyperscan regex support, see https://github.com/intel-go/nff-go/blob/master/examples/dpi/main/dpi.go 

- add default port and transport protocol during stream decoder creation

- database source: set default for windows to home directory

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

## Future Work

- add support for Kibana location maps
- detect SYN attack

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
- add a maltego.Die(msg string) function and use instead of panic(err), for centralized teardown and cleanup 
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

## Bugs / Errors

- ICS pcaps: failed to collect audit records from pcapng file: Unknown magic 73726576

## FAQs

- Is this an IDS?
- Can this handle high throughput

### Tooling

- Audit Record Anonymization for studying sensitive industrial networks

## DPI

- batch DPI calls per flow?
- add support for nDPI 4.14 Stable

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

- CC=x86_64-pc-linux-gcc GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -o nc-linux github.com/dreadl0ck/netcap/cmd
- GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -o nc-linux -ldflags="-L /usr/local/opt/libpcap/lib" github.com/dreadl0ck/netcap/cmd

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

## Install notes

Install ndpi on m1 mac:

  brew install ndpi


  brew install vectorscan