#!/bin/bash

# usage: mergecap.sh /path/to/caps
# output: merged.pcapng

rm -f merged.pcapng
while IFS= read -r line; do
    FILES+=("$line")
done < <(find $1 -type f -name "*.pcap" -o -name "*.pcapng" | sort)
declare -p FILES
mergecap -w merged.pcapng "${FILES[@]}"
du -h merged.pcapng