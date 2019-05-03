# NET.UTIL

*net.util* is a commandline tool that offers utility operations for netcap audit records.

## Description

The tool can be used to check the validity of generated audit records,
as well as converting netcap timestamps to human readable format.

Read more about this tool in the documentation: https://docs.netcap.io

## Usage examples

Check audit records field count offered by the structure VS emitted CSV:

    $ net.util -r TCP.ncap.gz -check

Perform check while using a custom separator string:

	$ net.util -r TCP.ncap.gz -check -sep '/'

Convert a netcap timestamp to UTC time:

    $ net.util -ts2utc 1505839354.197231
    2017-09-19 16:42:34.197231 +0000 UTC

## Help

    $ net.util -h
        -check
    	        check number of occurences of the separator, in fields of an audit record file
        -r string
                read specified file, can either be a pcap or netcap audit record file
        -sep string
                set separator string for csv output (default ",")
        -ts2utc string
                util to convert sencods.microseconds timestamp to UTC