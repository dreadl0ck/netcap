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

