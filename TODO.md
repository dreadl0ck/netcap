# TODOs

- make join sep configurable
- helper func for ToString() on array
- rename ToString

- OSPF: remove dummy OSPF.ncap file
- replace all strings.Join... with join util func
- performance: pre allocate array sizes and use indices

- gopacket TLS type
- log encoding errors for merged packets
- fix GRE Routing

Linux cross compilation:
- CC=x86_64-pc-linux-gcc GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -o nc-linux -i github.com/dreadl0ck/netcap/cmd
- GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -o nc-linux -ldflags="-L /usr/local/opt/libpcap/lib" -i github.com/dreadl0ck/netcap/cmd

- add ascii cast
- README

Benchmarks:
- add benchmarks writing through channels vs mutex
- add benchmarks: Concatenating Strings Builder vs byte slices etc

## Sensor

- client reuse conn?
- implement data export to elastic stack / influx 

## new protos

- NortelDiscovery
- MLDv2MulticastListenerReport
- ASExternalLSA

## update documentation

- LSA
- CiscoDiscoveryInfo
- EAPOL + Key
- VRRPv2
- EAP
- FDDI
- GRE
- BFD
- OSPF
- ModbusTCP
- MPLS
- LCM
- USB
- VXLAN
- Ipv6Fragment
- IPSec
- Geneve

# future

Future Development:
- scale to multi instance architecture
- data exporters + visualization dashboards / VR etc
- robustness testing / pentest
- performance assessment + optimizations

- labeling: how many unmatched alerts?
- labeling: switch to intelligence from eve.json

- json output
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
