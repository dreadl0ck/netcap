#!/bin/bash -e

# Invoke bash with -e flag to stop on errors.
# Beware of the gotchas: http://mywiki.wooledge.org/BashFAQ/105

# This script runs different configurations of the engine core on a single file,
# to compare the effects on performance and reported results.

# global config
export NC_DEBUG=true
export NC_OPTS=datagrams

NETCAP_BIN="net"
#f="FIRST-2015_Hands-on_Network_Forensics_PCAP/2015-03-17/snort.log.1426550408.pcap"
#f="pcaps/2017-09-19-traffic-analysis-exercise.pcap"
f="pcaps/snort.log.1426118407.pcap"
filename=$(basename -- "$f")
file=${filename%.pcap}

# clean previous data and recreate output directory
OUT="test-params"
rm -rf "${OUT}"
mkdir -p "${OUT}"

## 1.) Concurrency:
#      Workers and buffer size for packet queue
#
# flags:
# -workers  number of worker gorroutines for processing packets
# -pbuf     maximum number of packets that can be buffered in the channel feeding each worker

# Baseline: 1 Worker, no packet buffer
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-single-worker-0-pbuf.net" \
	-workers 1 \
	-pbuf 0

## a) Packet Buffer = 0

# NumCores Workers
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-0-pbuf.net" \
	-pbuf 0

# 1000 Workers
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-1000-workers-0-pbuf.net" \
	-workers 1000 \
	-pbuf 0

## b) Packet Buffer = 1000

# num cores workers
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-1000-pbuf.net" \
	-pbuf 1000

# 1000 workers
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-1000-workers-1000-pbuf.net" \
	-workers 1000 \
	-pbuf 1000

## 2.) Compression:
#      Variations in compression level and block size
#
#   To get any performance gains, you should at least be compressing more than 1 megabyte of data at the time.
#	  You should at least have a block size of 100k and at least a number of blocks that match the number of cores
#	  you would like to utilize, but about twice the number of blocks would be the best.
#
# flags:
# -compression-block-size   block size used for parallel compression (default: 1048576 (1MB))
# -compression-level        level of compression
# -membuf-size              size in bytes of in-memory buffer before feeding data to compressor, default: 12582912 (12MB)

## a) Block Size

# 1MB blocks, 12MB input buffer
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-1mb-blocks-compression.net" \
	-compression-block-size 1048576 \
	-membuf-size 12582912

# 10MB blocks, 120MB input buffer
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-10mb-blocks-compression.net" \
  -compression-block-size 10485760 \
  -membuf-size 125829120

## b) Compression Level

${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-max-speed.net" \
  -compression-level max-speed

${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-max-compression.net" \
  -compression-level max-compression

# no compression
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-no-compression.net" \
  -compression-level none

## 3.) TCP Reassembly:
#      Variations in TCP state machine configurations and stream timeouts
#
# flags:
# -flushevery               flush assembler every N packets
# -close-pending-timeout    close connections that have pending bytes
# -close-inactive-timeout   close connections that are inactive
# -ip4defrag                Defragment IPv4 packets
#	-checksum                 check TCP checksum
#	-nooptcheck               do not check TCP options (useful to ignore MSS on captures with TSO)
#	-ignorefsmerr             ignore TCP FSM errors
#	-allowmissinginit         support streams without SYN/SYN+ACK/ACK sequence
# -remove-closed-streams    remove tcp streams that receive a FIN or RST packet from the stream pool
#	-sbuf-size                size for channel used to pass data to the stream decoders. default is unbuffered

# Baseline: disable reassembly
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-no-reassembly.net" \
	-reassemble-connections false

## a) Flushing interval variations

# 100 packets
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-100-flushevery.net" \
	-flushevery 100

# 1000 packets
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-1000-flushevery.net" \
	-flushevery 1000

# 10000 packets
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-10000-flushevery.net" \
	-flushevery 10000

## b) Timeout variations

# 1m
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-1m-timeouts.net" \
	-close-pending-timeout 1m \
	-close-inactive-timeout 1m

# 10m
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-10m-timeouts.net" \
	-close-pending-timeout 10m \
	-close-inactive-timeout 10m

# 1h
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-1h-timeouts.net" \
	-close-pending-timeout 1h \
	-close-inactive-timeout 1h

## c) TCP state machine variations

# allow missing init
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-allowmissinginit.net" \
	-allowmissinginit true

# deny missing init
${NETCAP_BIN} capture -read "$f" \
  -out "${OUT}/${file}-numcores-workers-denymissinginit.net" \
  -allowmissinginit false

# remove closed streams
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-remove-closed-streams.net" \
	-remove-closed-streams true

# keep closed streams
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-keep-closed-streams.net" \
	-remove-closed-streams false

# loose
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-reassembly-loose.net" \
  -checksum=false \
  -nooptcheck=true \
  -ignorefsmerr=true \
  -allowmissinginit=true

# strict
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-reassembly-strict.net" \
	-checksum=true \
  -nooptcheck=false \
  -ignorefsmerr=false \
  -allowmissinginit=false

## d) TCP stream processor buffering

# 10 streams
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-10-sbuf.net" \
	-sbuf-size 10

# 100 streams
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-100-sbuf.net" \
	-sbuf-size 100

# 1000 streams
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-1000-sbuf.net" \
	-sbuf-size 1000

## 4.) Decoder Selection
#      Variations in including and excluding decoders, to measure the impact on performance
#      bpf syntax: https://biot.com/capstats/bpf.html
# flags:
# -include   include specific decoders
# -exclude   exclude specific decoders
# -bpf       use a berkeley packet filter

# Only include Ethernet,IPv4,IPv6,TCP,UDP
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-eth-ip-tcp-udp.net" \
	-include Ethernet,IPv4,IPv6,TCP,UDP

# Ethernet,IPv4,IPv6,TCP with bpf for HTTP traffic only
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-httponly-bpf.net" \
	-include Ethernet,IPv4,IPv6,TCP,UDP \
	-bpf "tcp port 80 and tcp port 443"

# Exclude all custom decoders
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-no-customdecoders.net" \
	-exclude TLSClientHello,TLSServerHello,HTTP,Connection,DeviceProfile,IPProfile,File,POP3,Software,Service,Credentials,SSH,Vulnerability,Exploit,Mail

# Include only custom decoders
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-only-customdecoders.net" \
	-include TLSClientHello,TLSServerHello,HTTP,Connection,DeviceProfile,IPProfile,File,POP3,Software,Service,Credentials,SSH,Vulnerability,Exploit,Mail

## 5.) Resolvers
#      Different correlation configs
# flags:
# -reverse-dns  resolve ips to domains via the operating systems default dns resolver
# -local-dns    resolve DNS locally via hosts file in the database dir
# -macDB        use mac to vendor database for device profiling
# -ja3DB        use ja3 database for device profiling
# -serviceDB    use serviceDB for device profiling
# -geoDB        use geolocation for device profiling

# TODO: add resolver tests

## 6.) DPI
#      Performance impact of deep packet inspection
# flags:
# -dpi          use DPI for device profiling

# enable DPI
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-dpi.net" \
	-dpi

## 7.) File extraction
#      Performance impact of file extraction
# flags:
# -fileStorage  save files to disk

# extract files
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-extract-files.net" \
	-fileStorage files

## 8.) Connection extraction
#      Performance impact of connection extraction
# flags:
# -conns  save connections to disk

# save connections
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-extract-conns.net" \
	-conns

## 9.) IO Settings
#      Different IO configurations
# flags:
# -ignore-unknown   disable writing unknown packets into a pcap file
# -csv
# -json
# -null
# -context
# -payload
# -entropy

# ignore unknown packets
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-ignore-unknown.net" \
	-ignore-unknown

# output CSV
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-csv.net" \
	-csv

# output JSON
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-json.net" \
	-json

# write no data to disk
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-null.net" \
	-null

# no packet context
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-no-context.net" \
	-context=false

# store payloads for certain protocols
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-payload.net" \
	-payload

# calculate entropy for certain packet payloads
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-entropy.net" \
	-entropy

## 10.) Gopacket Decoder Options
# flags:
# -opts   select decoding options

# use gopacket default opts
${NETCAP_BIN} capture -read "$f" \
	-out "${OUT}/${file}-numcores-workers-gopacket-default-opt.net" \
	-opts default

# Summary Logs

echo "Execution time:"
grep --color=always "execution time" "${OUT}"/*/netcap.log | awk -F: '{print $2 "     " $1}'

echo "Total bytes of data written to disk:"
grep --color=always "data written to disk" "${OUT}"/*/netcap.log | awk -F: '{print $2 FS $3"     " $1}'

echo "Extracted HTTP audit records:"
grep --color=always " HTTP " "${OUT}"/*/netcap.log | awk -F: '{print $2 "     " $1}'

