# NET.UTIL

*net util* is a commandline tool that offers utility operations for netcap audit records.

## Description

The tool can be used to check the validity of generated audit records,
as well as converting netcap timestamps to human-readable format.

Read more about this tool in the documentation: https://docs.netcap.io

## Usage examples

Check audit records field count offered by the structure VS emitted CSV:

    $ net util -read TCP.ncap.gz -check

Perform check while using a custom separator string:

	$ net util -read TCP.ncap.gz -check -sep '/'

Convert a netcap timestamp to UTC time:

    $ net util -ts2utc 1505839354.197231
    2017-09-19 16:42:34.197231 +0000 UTC

## Help

    $ net util -h
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
    
    util tool usage examples:
            $ net util -read TCP.ncap.gz -check
            $ net util -read TCP.ncap.gz -check -sep '/'
            $ net util -ts2utc 1505839354.197231
    
      -check=false: check number of occurences of the separator, in fields of an audit record file
      -config="": read configuration from file at path
      -env=false: print netcap environment variables and exit
      -gen-config=false: generate config
      -interfaces=false: print netcap environment variables and exit
      -membuf-size=10485760: set size for membuf
      -read="": read specified audit record file
      -sep=",": set separator string for csv output
      -ts2utc="": util to convert seconds.microseconds timestamp to UTC
      -version=false: print netcap package version and exit
