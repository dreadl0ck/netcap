#!/bin/sh
exec /opt/netcap/magika/ld-linux-x86-64.so.2 --library-path /opt/netcap/magika /opt/netcap/magika/magika "$@"
