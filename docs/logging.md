---
description: Logging options
---

# Logging

## Quiet mode

Netcap writes a general summary to stdout, if you wish to disable output entirely use the **-quiet** flag:

```text
$ net capture -quiet
```

When the quiet mode is used, the output is instead written into the **netcap.log** file in the directory where netcap is executed from.

## Decoding errors

Errors when parsing packets are logged by default into the **errors.log** file in the current directory.

Each log entry contains a hex dump of the entire packet and the error message or stack trace.

## Log files in debug mode

The following log file are produced when running with the **-debug** flag:

* debug.log: general debug messages
* reassembly.log: tcp stream reassembly debug logs

## Automatic removal of empty log files

Similar to how empty audit record files are handled, NETCAP automatically removes log files that are empty after flushing and closing their file handles at the end of packet capture or processing.

This applies to all log files created during execution:

* netcap.log
* collector.log
* decoder.log
* io.log
* resolvers.log
* reassembly.log
* db.log
* errors.log

When a log file contains no data (size = 0 bytes) after being flushed and closed, it is automatically deleted to avoid cluttering the output directory with empty files. This behavior ensures that only log files containing actual log entries are kept.

**Note**: On Windows systems, there may be timing issues that prevent empty log file removal in some cases, similar to the behavior with empty audit record files.

