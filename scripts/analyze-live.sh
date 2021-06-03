#!/bin/bash

# usage: analyze-live.sh <interface>

net capture -iface "$1" \
  -out "live.net" \
  -opts datagrams \
  -reverse-dns \
  -geoDB \
  -promisc=false \
  -elastic \
  -debug \
  -fileStorage files \
  -elastic-user elastic \
  -elastic-pass "$ELASTIC_PASS" \
  -kibana "$KIBANA_URL" \
  -metrics "localhost:6060"