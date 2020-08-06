# NET.DUMP

*net dump* is a commandline tool that provides reading netcap files and conversion of the audit records to various formats.

## Description

Output can be formatted as Table or separated by tabs, or a custom separator string.
Export to CSV and JSON is possible, for CSV fields can be filtered.

Read more about this tool in the documentation: https://docs.netcap.io

## Usage examples

Dump all audit records in the specified file to stdout:

    $ net dump -read TCP.ncap.gz

Show all fields for the audit record type in the file:

    $ net dump -fields -read TCP.ncap.gz

Dump the specified fields in the specified order as CSV:

    $ net dump -read TCP.ncap.gz -select Timestamp,SrcPort,DstPort > tcp.csv

## Help

    $ net dump -h
                           / |
     _______    ______   _10 |_     _______   ______    ______
    /     / \  /    / \ / 01/  |   /     / | /    / \  /    / \
    0010100 /|/011010 /|101010/   /0101010/  001010  |/100110  |
    01 |  00 |00    00 |  10 | __ 00 |       /    10 |00 |  01 |
    10 |  01 |01001010/   00 |/  |01 \_____ /0101000 |00 |__10/|
    10 |  00 |00/    / |  10  00/ 00/    / |00    00 |00/   00/
    00/   10/  0101000/    0010/   0010010/  0010100/ 1010100/
                                                      00 |
    Network Protocol Analysis Framework               00 |
    created by Philipp Mieden, 2018                   00/
    v0.5
    
    dump tool usage examples:
            $ net dump -read TCP.ncap.gz
            $ net dump -fields -read TCP.ncap.gz
            $ net dump -read TCP.ncap.gz -select Timestamp,SrcPort,DstPort > tcp.csv
    
      -begin="(": begin character for a structure in CSV output
      -config="": read configuration from file at path
      -csv=false: print output data as csv with header line
      -end=")": end character for a structure in CSV output
      -fields=false: print available fields for an audit record file and exit
      -gen-config=false: generate config
      -header=false: print audit record file header and exit
      -json=false: print as JSON
      -membuf-size=10485760: set size for membuf
      -read="": read specified file, can either be a pcap or netcap audit record file
      -select="": select specific fields of an audit records when generating csv or tables
      -sep=",": set separator string for csv output
      -struc=false: print output as structured objects
      -struct-sep="-": separator character for a structure in CSV output
      -table=false: print output as table view (thanks @evilsocket)
      -tsv=false: print output as tab separated values
      -utc=false: print timestamps as UTC when using select csv
      -version=false: print netcap package version and exit
