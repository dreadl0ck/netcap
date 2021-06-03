#!/bin/bash

# usage: analyze-dataset.sh /path/to/caps

# todo: use find cmd
for f in $1/*/*.pcap
do
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
done