# TODOs

- add ascii cast
- README

Benchmarks:
- add benchmarks writing through channels vs mutex
- add benchmarks: Concatenating Strings Builder vs byte slices etc

## Sensor

- client reuse conn?
- implement data export to elastic stack / influx 

## new protos

- MLDv2MulticastListenerReport
- VRRPv2
- FDDI
- GRE
- EAPOL + Key
- EAP
- CiscoDiscoveryInfo
- CDPHello
- CDPEnergyWise
- BFD
- ASExternalLSA
- OSPF
- LSA

## update documentation

- ModbusTCP
- MPLS
- LCM
- USB
- VXLAN
- Fragment
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
