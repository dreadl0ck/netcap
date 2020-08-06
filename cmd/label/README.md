# NET.LABEL

*net label* is a commandline tool to apply classification labels to netcap audit records.

## Description

As a source for the alerts, the source pcap file is scanned with suricata.
*Netcap* parses the suricata output and maps it to the previously generated netcap audit records.
A labeled comma-separated values (CSV) file will be generated for each audit record type.

Read more about this tool in the documentation: https://docs.netcap.io

## Usage examples

Scan input pcap and create labeled csv files by mapping audit records in the current directory:

    $ net label -read traffic.pcap

Scan input pcap and create output files by mapping audit records from the output directory:

    $ net label -read traffic.pcap -out output_dir

Abort if there is more than one alert for the same timestamp:

    $ net label -read taffic.pcap -strict

Display progress bar while processing input (experimental):

    $ net.label -read taffic.pcap -progress

Append classifications for duplicate labels:

    $ net.label -read taffic.pcap -collect

## Help

    $ net label -h
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
    
    label tool usage examples:
            $ net label -read traffic.pcap
            $ net label -read traffic.pcap -out output_dir
            $ net label -read taffic.pcap -progress
            $ net label -read taffic.pcap -collect
    
      -collect=false: append classifications from alert with duplicate timestamps to the generated label
      -config="": read configuration from file at path
      -custom="": use custom mappings at path
      -debug=false: toggle debug mode
      -description=false: use attack description instead of classification for labels
      -disable-layers=false: do not map layer types by timestamp
      -exclude="": specify a comma separated list of suricata classifications that shall be excluded from the generated labeled csv
      -gen-config=false: generate config
      -out="": specify output directory, will be created if it does not exist
      -progress=false: use progress bars
      -read="": use specified pcap file to scan with suricata
      -sep=",": set separator string for csv output
      -strict=false: fail when there is more than one alert for the same timestamp
      -suricata-config="/usr/local/etc/suricata/suricata.yaml": set the path to the suricata config file
      -version=false: print netcap package version and exit
