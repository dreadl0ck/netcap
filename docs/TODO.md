# TODOs

netcap-try-1  | 2025-11-05T11:53:55.144412918Z 2025/11/05 11:53:55 [DPI] Reset() called, disabled=false
netcap-try-1  | 2025-11-05T11:53:55.144417196Z 2025/11/05 11:53:55 [DPI] Resetting DPI state with modules:
netcap-try-1  | 2025-11-05T11:53:55.190402934Z 2025/11/05 11:53:55 [DPI] Reset() returning
netcap-try-1  | 2025-11-05T11:53:55.245001582Z 2025/11/05 11:53:55 [WebUI] Memory after cleanup (session 9c12dcde77a5053680fe40aab9c8da6e): Heap Alloc=974 MB, Heap Sys=1.4 GB, Goroutines=10
netcap-try-1  | 2025-11-05T11:53:55.245036016Z 2025/11/05 11:53:55 [WebUI] Memory cleanup completed for session 9c12dcde77a5053680fe40aab9c8da6e
netcap-try-1  | 2025-11-05T11:53:55.246852676Z 2025/11/05 11:53:55 [WebUI] Job processing completed: job 1/2, session=9c12dcde77a5053680fe40aab9c8da6e
netcap-try-1  | 2025-11-05T11:53:55.246874687Z 2025/11/05 11:53:55 [WebUI] Job received from queue: processing job 2/482, session=ed02b4cd33de554c5e9457e0befec086, file=/data/netcap-service/pcaps/ssh_unidirectional.pcap
netcap-try-1  | 2025-11-05T11:53:55.246897580Z 2025/11/05 11:53:55 [WebUI] Starting in-process analysis for session ed02b4cd33de554c5e9457e0befec086
netcap-try-1  | 2025-11-05T11:53:55.246902860Z 2025/11/05 11:53:55 [SessionManager] Updating session ed02b4cd33de554c5e9457e0befec086 status: queued -> processing
netcap-try-1  | 2025-11-05T11:53:55.246908080Z 2025/11/05 11:53:55 [WebUI] Memory before analysis (session ed02b4cd33de554c5e9457e0befec086): Heap Alloc=974 MB, Heap Sys=1.4 GB, Goroutines=10
netcap-try-1  | 2025-11-05T11:53:55.257466261Z WARNING: lpi_init_library has already been called
netcap-try-1  | 2025-11-05T11:53:57.223571822Z SIGSEGV: segmentation violation
netcap-try-1  | 2025-11-05T11:53:57.223659796Z PC=0x7fca283536d0 m=7 sigcode=1 addr=0x7fc9e0478950
netcap-try-1  | 2025-11-05T11:53:57.223669854Z signal arrived during cgo execution
netcap-try-1  | 2025-11-05T11:53:57.223676096Z
netcap-try-1  | 2025-11-05T11:53:57.223681537Z goroutine 21 gp=0xc0000f4380 m=7 mp=0xc0000a0008 [syscall]:
netcap-try-1  | 2025-11-05T11:53:57.223687718Z runtime.cgocall(0x175cc90, 0xc0007df280)
netcap-try-1  | 2025-11-05T11:53:57.223694060Z 	/usr/local/go/src/runtime/cgocall.go:167 +0x4b fp=0xc0007df258 sp=0xc0007df220 pc=0x481d8b
netcap-try-1  | 2025-11-05T11:53:57.223708647Z github.com/dreadl0ck/go-dpi/modules/wrappers._Cfunc_ndpiDestroy()
netcap-try-1  | 2025-11-05T11:53:57.223718095Z 	_cgo_gotypes.go:186 +0x3a fp=0xc0007df280 sp=0xc0007df258 pc=0x121c61a
netcap-try-1  | 2025-11-05T11:53:57.223744625Z github.com/dreadl0ck/go-dpi/modules/wrappers.NewNDPIWrapper.func2()
netcap-try-1  | 2025-11-05T11:53:57.223752048Z 	/go-dpi/modules/wrappers/nDPI_wrapper.go:541 +0xf fp=0xc0007df290 sp=0xc0007df280 pc=0x121df6f
netcap-try-1  | 2025-11-05T11:53:57.223758280Z github.com/dreadl0ck/go-dpi/modules/wrappers.(*NDPIWrapper).DestroyWrapper(0x12149fd?)
netcap-try-1  | 2025-11-05T11:53:57.223772737Z 	/go-dpi/modules/wrappers/nDPI_wrapper.go:583 +0x16 fp=0xc0007df2a0 sp=0xc0007df290 pc=0x121d536
netcap-try-1  | 2025-11-05T11:53:57.223780041Z github.com/dreadl0ck/go-dpi/modules/wrappers.(*WrapperModule).Destroy(0xc04dda4580?)
netcap-try-1  | 2025-11-05T11:53:57.223786854Z 	/go-dpi/modules/wrappers/wrappers.go:89 +0x2f fp=0xc0007df2c8 sp=0xc0007df2a0 pc=0x121bd8f
netcap-try-1  | 2025-11-05T11:53:57.223793807Z github.com/dreadl0ck/go-dpi.Destroy()




check OOM killed: sudo dmesg -T | grep -i "killed process"

check for C mem usage: LD_PRELOAD=/usr/lib/libtcmalloc.so <your_program>

check C resource cleanup in go-dpi

remove field filtering count collection in backend - explore page show fields

logging cleanup

audit records page layer order

FIX autompletion: close suggestion dropdown when user clicks enter! only open when activated with tab, maybe close after a few seconds of no action?
rules add support for triggering alert when a certain threshold is reached (eg rule triggered 100 times -> alert)


now integrate into capture command: right after audit record is created, check it against filter and discard if not matching. Then match against any rules for that type and fire alert if it matches rule.

webUI: add Rule page, where rules can be created, edited (with syntax highlighting for expressions!) and deleted. Add Alerts page where are fired Alerts will be displayed.

Collect performance metrics for performance.log about filter and rule execution times


load rules/examples and enable filtering by tag in UI


review the entire implementation for potential issues

update engine: rules / filters need to be executed in batches so that large amounts of data can be processed.

Alert: eg: any credential audit record

Audit records page: view records: only show max 500 results, render JSON data, display unix timestamp human readable

------

implement bug reporting in local mode
cleanup old service directory

add detailed field descriptions for each protocol and show in explore view when selecting a field

netcap core should produce info which fields contain data for the audit records, so that UI can use this only show fields that make sense for filtering, without having to parse the entire data again.

always allow to drag and drop files for upload on the Analyze menu item, even if user is on a different page. Switch to analyze page automatiaclly and start upload

bpf filter doesnt seem to be applied correctly, debug

add local dev mode for webUI

Visualize and Explore Page: add toggle to turn Legend on / off

DHCP fingerprinting results for DeviceProfile and IPProfile

geolocation chart

visualize internal VS external IPs in dump

merge local and service mode servers

expr for filtering audit records

---

for local builds always show the short commit hash to the version embedded in the binary in the webUI

try-service: crash reporting mechanism: when the service panics and crashes, we need the full service log, and all netcap logfiles copied and archived together with the input pcap file for reproduction. An alert should be fired via email. add support to connect an SMTP service to send alert emails to an administrator.

add custom data support for dbs and integrate it in UI

Graph view page: threeJS node based graph view to explore data relations.

Flow view page: render interactive, horizontal timeline of activity from different hosts (hosts vertical), and display additional information when hovering over hosts

Alerts page
Rules page

---

- dbs: TorDB (torlookup) databases
  - https://www.dan.me.uk/tornodes
  - https://github.com/alireza-rezaee/tor-nodes?tab=readme-ov-file


- docs iteration
- tests iteration

-----

  for f in *.pcap *.pcapng; do [ -f "$f" ] && net capture -y -read "$f" -out "${f%.*}"; done

with break on interrupt:

  for f in *.pcap *.pcapng; do [ -f "$f" ] && { net capture -read "$f" -out "${f%.*}" || break; }; done

or with trap:

  trap 'exit 130' INT; for f in *.pcap *.pcapng; do [ -f "$f" ] && net capture -read "$f" -out "${f%.*}"; done

or

  find . -maxdepth 1 \( -name "*.pcap" -o -name "*.pcapng" \) -type f -exec sh -c 'net capture -read "$1" -out "${1%.*}"' _ {} \;

VSCode extension to view netcap audit records?

switch to gopacket/reassembly and tcpassembly

add internal package

implement Alerts and Rules

go-dpi idea: generate port lookup table based on IANA spec for first guess for go classifier

----

test suite:
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

Install ndpi on m1 mac:

  brew install ndpi

- ip and domain reputation
  - domain age: mark domains registered in the past 30 days
  - categorize domains (sector etc)
  - integrate feeds from https://threatview.io
- add config to apply extra asset info to audit records: eg employee workstations in internal network etc

- add dpi / nodpi arm64 builds for linux
- extend api with context to allow stopping collector
- improve unit tests
- https://github.com/dreadl0ck/netcap/issues/19
- add test for reading SLL pcaps: https://wiki.wireshark.org/SLL
- implement rule engine
- check:

panic: runtime error: index out of range [-1]

goroutine 38175 [running]:
github.com/dreadl0ck/netcap/reassembly.(*reassemblyObject).Info(0xc0003ea078, 0x177, 0x0)
/Users/alien/go/src/github.com/dreadl0ck/netcap/reassembly/reassemblyObject.go:82 +0xd9
github.com/dreadl0ck/netcap/decoder/stream/tcp.(*tcpConnection).ReassembledSG(0xc02c9fb040, 0x58a36d0, 0xc0003ea078, 0x0, 0x0)
/Users/alien/go/src/github.com/dreadl0ck/netcap/decoder/stream/tcp/tcpConnection.go:243 +0x77
github.com/dreadl0ck/netcap/reassembly.(*Assembler).sendToConnection(0xc0003ea000, 0xc0187eab20, 0xc0187eac18, 0xf385bb1)
/Users/alien/go/src/github.com/dreadl0ck/netcap/reassembly/assembler.go:787 +0x171
github.com/dreadl0ck/netcap/reassembly.(*Assembler).skipFlush(0xc0003ea000, 0xc0187eab20, 0xc0187eac18)
/Users/alien/go/src/github.com/dreadl0ck/netcap/reassembly/assembler.go:901 +0xb4
github.com/dreadl0ck/netcap/reassembly.(*Assembler).closeConn(0xc0003ea000, 0xc0187eab20)
/Users/alien/go/src/github.com/dreadl0ck/netcap/reassembly/assembler.go:1114 +0x75
github.com/dreadl0ck/netcap/reassembly.(*Assembler).FlushAllProgress.func1(0xc0003ea000, 0xc066ec29a0, 0xc0647127b0, 0xc0187eab20)
/Users/alien/go/src/github.com/dreadl0ck/netcap/reassembly/assembler.go:1098 +0x35
created by github.com/dreadl0ck/netcap/reassembly.(*Assembler).FlushAllProgress
/Users/alien/go/src/github.com/dreadl0ck/netcap/reassembly/assembler.go:1097 +0x188


- resolver API: add ip blacklist and integrate feeds
- resolvers: integrate IP and domain reputation feeds

- document: stateful VS stateless packet decoders (eg UDP vs Connection)

## NEXT

- implement support for MLDv2MulticastListenerReport packets
- create elastic indices: netcap-ospf does already exist?
- censor passwords from dumped config in netcap.log
- log hint to use pcapfix tool for errors during pcap processing like 'capture length exceeds snap length'
- add force flag to disable prompts: -y flag exists (renamed from -noprompt)
- overwrite check does not include other formats than ncap or ncap.gz
- service detection seems racy, debug
- add flag to disable writing files to disk (but: still generating the audit records
- unify flag naming and update docs, eg fileStorage

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
- add PPP audit records

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
- regenerate from latest nmap-services database and automate
- port CIP, ENIP and ModbusTCP decoding to stream decoders, add to docs that decodeOpt datagrams must be set for the packet based decoders to be called

- database source: set default for windows to home directory
- dbs update script
- script netcap installation, add setup check util command 

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
