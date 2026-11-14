# Logging

Netcap produces three kinds of output: console and log files, audit records, and [health artifacts](evidence.md). When you collect diagnostics, note the output directory and the exact command you ran.

## Quiet mode

```sh
net capture -read traffic.pcap -out quiet-audit -quiet -dpi=false
```

`-quiet` reduces console output. Decoding and evidence files are unaffected. Check the log files in the output directory to see whether the run succeeded.

## Decoding errors

`-log-errors` turns on verbose logging of packet decoding errors. These logs can contain raw packet bytes, including credentials and personal data. Store them with the same access controls as the capture. For a public bug report, reduce the capture to a small sanitized sample.

## Debug logs

`capture -debug` writes extra diagnostics. Depending on what ran, you will find `debug.log`, `errors.log`, `reassembly.log` and logs for other subsystems. Look in the output directory you passed with `-out`.

## Empty log files

Some writers delete empty log files on a clean shutdown, so a missing log does not tell you whether a subsystem ran. If the process was killed, buffers may not have been flushed either. Check the exit status and the [health artifacts](evidence.md).

## MCP server

`net mcp` uses stdout for JSON-RPC. Keep logs on stderr. Shell banners or log redirection to stdout break the MCP client.
