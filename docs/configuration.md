---
description: Flags, explicit environment overrides and feature-specific files.
---

# Configuration

## Command-line options

Each subcommand owns its options. Inspect the installed executable, rather than
copying a help listing from a different release:

```sh
net capture -h
net dump -h
net investigate -h
net util -h
```

Use `-flag=false` for Boolean false values. A space-separated `false` can become
a positional argument instead of disabling the option.

## Environment overrides

Use the environment variable declared by the flag. Names are not uniformly
derived from spelling: `NC_READ` selects capture input, whereas
`NETCAP_DBS_URL` selects a database publisher.

```sh
NC_READ=example.pcap net capture -out environment-audit
NC_CONFIG_ROOT=/srv/netcap-config net util -download-dbs
```

Use the same root when capturing. The second command installs into
`/srv/netcap-config/dbs`, not directly into `/srv/netcap-config`.

| Setting | Meaning |
| --- | --- |
| `NC_CONFIG_ROOT` | Configuration parent; community data lives in its `dbs/` child |
| `NETCAP_DBS_URL` | Optional database publisher URL |
| `NC_DBS_APPROVALS` + `NC_DBS_APPROVALS_SHA256` | Paired independent registry override for private publishers |
| `NC_GEO_PROVIDERS` | DB-IP/optional GeoLite2 provider order |
| `NETCAP_MCP_ADMIN_TOKEN` | HTTP MCP authorization; does not protect general WebUI routes |

## Feature-specific configuration

| Feature | File and entry point |
| --- | --- |
| Detection rules | YAML supplied with `capture -rules` |
| Network detections | JSON supplied with `-network-detection-config` |
| Behavior | Baseline selected with `-behavior-baseline`; policy selected with `-behavior-policy` |
| Reverse proxy | YAML supplied with `proxy -proxy-config` |
| Protocol experiments | Versioned JSON passed to the relevant `investigate` command's `-spec` |

These are separate parsers with separate schemas. Read the corresponding guide
before composing a file. A malformed feature file should not be replaced with a
generic configuration guessed from another subcommand.

## Generic config compatibility flags

Go v0.15.2 still exposes legacy `-config`/`-gen-config` flags in some help output,
but generic generation is unimplemented and a general config-file workflow is
not supported by these docs. Earlier instructions recommending
`net capture -gen-config > capture.conf` were incorrect. Use verified flags,
environment overrides and the feature-specific files above.

## Entry-point behavior

| Invocation | HTTP lifecycle |
| --- | --- |
| `capture -read file.pcap` | Finishes and exits after analysis |
| `capture -read file.pcap -http 127.0.0.1:8080` | Keeps the local UI running |
| `capture -service -http 127.0.0.1:7070` | Upload/session service |
| `mcp` | Stdio MCP plus an internal loopback WebUI |

See [resource budgets](workers.md) before interpreting per-stream or per-decoder
limits as a process-wide memory or disk guarantee.
