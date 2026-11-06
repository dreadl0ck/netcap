# Logging

Capture logs, audit records and health artifacts answer different questions.
Record the output directory and exact command when collecting diagnostics.

## Quiet mode

```sh
net capture -read traffic.pcap -out quiet-audit -quiet -dpi=false
```

`-quiet` reduces console output; it does not disable decoding, evidence files or
every subsystem's diagnostics. Inspect the resulting logs rather than treating
an empty terminal as success.

## Decoding errors

`-log-errors` controls verbose packet-decoding error logging. Error logs may
include raw packet bytes and therefore credentials or personal data. Preserve
them with the capture's access controls; use a minimal sanitized reproducer for
public bug reports.

## Log files in debug mode

`capture -debug` enables additional diagnostics. Depending on enabled paths,
logs can include `debug.log`, `errors.log`, `reassembly.log` and subsystem logs.
Use actual startup/output paths rather than assuming every file is created in
the shell's original working directory.

## Automatic removal of empty log files

Some writers remove empty files at orderly shutdown. Missing empty logs are not
evidence that a subsystem ran successfully; abrupt termination can also prevent
normal flush/cleanup. Check exit status and [health artifacts](evidence.md).

For the stdio MCP server, stdout is JSON-RPC transport. Keep operational
diagnostics on stderr; shell banners or redirected logs on stdout break clients.
