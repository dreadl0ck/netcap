# NET.DUMP

*net.dump* is a commandline tool that provides reading netcap files and conversion of the audit records to various formats.

## Description

Output can be formatted as Table or separated by tabs or a custom separator string.
Export to CSV and JSON is possible, for CSV fields can be filtered.

Read more about this tool in the documentation: https://docs.netcap.io

## Usage examples

Dump all audit records in the specified file to stdout:

    $ net.dump -r TCP.ncap.gz

Show all fields for the audit record type in the file:

    $ net.dump -fields -r TCP.ncap.gz

Dump the specified fields in the specified order as CSV:

    $ net.dump -r TCP.ncap.gz -select Timestamp,SrcPort,DstPort > tcp.csv

## Help

    $ net.dump -h
        -begin string
                begin character for a structure in CSV output (default "(")
        -csv
                print output data as csv with header line
        -end string
                end character for a structure in CSV output (default ")")
        -fields
                print available fields for an audit record file and exit
        -header
                print audit record file header and exit
        -r string
                read specified file, can either be a pcap or netcap audit record file
        -select string
                select specific fields of an audit records when generating csv or tables
        -sep string
                set separator string for csv output (default ",")
        -struc
                print output as structured objects
        -struct-sep string
                separator character for a structure in CSV output (default "-")
        -table
                print output as table view (thanks @evilsocket)
        -tsv
                print output as tab separated values
        -utc
                print timestamps as UTC when using select csv
        