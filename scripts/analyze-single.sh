#!/bin/bash

# usage: analyze-single.sh /path/to/pcap/file

f="$1"
filename=$(basename -- "$f")
file=${filename%.pcap}
net capture -read "$f" \
	-out "${file}.net" \
	-opts datagrams \
	-local-dns \
	-geoDB \
	-elastic \
	-fileStorage files \
	-elastic-user elastic \
	-elastic-pass "$ELASTIC_PASS" \
	-kibana "$KIBANA_URL"