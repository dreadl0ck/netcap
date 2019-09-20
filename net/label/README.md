# NET.LABEL

*net.label* is a commandline tool to apply classification labels to netcap audit records.

## Description

As a source for the alerts, the source pcap file is scanned with suricata.
*Netcap* parses suricata's output and maps it to the previously generated netcap audit records.
A labeled comma-separated values (CSV) file will be generated for each audit record type.

Read more about this tool in the documentation: https://docs.netcap.io

## Usage examples

Scan input pcap and create labeled csv files by mapping audit records in the current directory:

    $ net.label -r traffic.pcap

Scan input pcap and create output files by mapping audit records from the output directory:

    $ net.label -r traffic.pcap -out output_dir

Abort if there is more than one alert for the same timestamp:

    $ net.label -r taffic.pcap -strict

Display progress bar while processing input (experimental):

    $ net.label -r taffic.pcap -progress

Append classifications for duplicate labels:

    $ net.label -r taffic.pcap -collect

## Help

    $ net.label -h
        -collect
                append classifications from alert with duplicate timestamps to the generated label
        -debug
                toggle debug mode
        -description
                use attack description instead of classification for labels
        -disable-layers
                do not map layer types by timestamp
        -exclude string
                specify a comma separated list of suricata classifications that shall be excluded from the generated labeled csv
        -out string
                specify output directory, will be created if it does not exist
        -progress
                use progress bars
        -r string
                (required) read specified file, can either be a pcap or netcap audit record file
        -sep string
                set separator string for csv output (default ",")
        -strict
                fail when there is more than one alert for the same timestamp
        -suricata-config string
                set the path to the suricata config file (default "/usr/local/etc/suricata/suricata.yaml")