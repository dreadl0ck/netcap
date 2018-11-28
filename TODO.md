# TODOs

Benchmarks:
- add benchmarks writing through channels vs mutex
- add benchmarks: 5.5  Concatenating Strings

- comments, code cleanup, renaming
- golang: propose linting after error until end of current function?

## Sensor

- TEST: gzip data on disk
- client reuse conn?

- don't write packets to disk option -> export
- implement data export to elastic stack / influx 

## new protos

- IPSec
- MLDv2MulticastListenerReport
- Geneve
- VXLAN
- Fragment

# future

- how many unmatched alerts?
- switch to intelligence from eve.json for labeling
- json output
- check if there are spots left where using a strings.Builder makes sense
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
- plugins?
- integrate labeling function for YARA
- go-dpi classifiers?
