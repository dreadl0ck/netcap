---
description: Command-line flags, environment variables and feature-specific files.
---

# Configuration

## Command-line options

Each subcommand has its own options. Read them from the executable you installed:

```sh
net capture -h
net dump -h
net investigate -h
net util -h
```

Write Boolean false as `-flag=false`. With a space, as in `-flag false`, the `false` is read as a positional argument and the option stays on.

## Environment overrides

Every flag has an environment variable, shown in `-h`. The names do not follow one pattern: `NC_READ` sets the capture input, `NETCAP_DBS_URL` sets the database publisher.

```sh
NC_READ=office-lan.pcap net capture -out environment-audit
NC_CONFIG_ROOT=/srv/netcap-config net util -download-dbs
```

Set the same `NC_CONFIG_ROOT` when you capture. The second command installs into `/srv/netcap-config/dbs`.

| Setting                                        | Meaning                                                                 |
| ---------------------------------------------- | ----------------------------------------------------------------------- |
| `NC_CONFIG_ROOT`                               | Configuration parent; community data lives in its `dbs/` child          |
| `NETCAP_DBS_URL`                               | Optional database publisher URL                                         |
| `NC_DBS_APPROVALS` + `NC_DBS_APPROVALS_SHA256` | Set both together to use a private publisher                            |
| `NC_GEO_PROVIDERS`                             | DB-IP/optional GeoLite2 provider order                                  |
| `NETCAP_MCP_ADMIN_TOKEN`                       | Authorizes the HTTP MCP endpoint. It does not protect the WebUI routes. |

## Feature-specific configuration

| Feature              | File and entry point                                                                 |
| -------------------- | ------------------------------------------------------------------------------------ |
| Detection rules      | YAML supplied with `capture -rules`                                                  |
| Network detections   | JSON supplied with `-network-detection-config`                                       |
| Behavior             | Baseline selected with `-behavior-baseline`; policy selected with `-behavior-policy` |
| Reverse proxy        | YAML supplied with `proxy -proxy-config`                                             |
| Protocol experiments | Versioned JSON passed to the relevant `investigate` command's `-spec`                |

Each file has its own parser and schema. Read the matching guide before you write one.

## Generic config compatibility flags

There is no general config file. `-config` and `-gen-config` still appear in some help output but do nothing useful, and `net capture -gen-config > capture.conf` does not produce a working file. Use flags, environment variables and the feature files above.

## Entry-point behavior

| Invocation                                     | HTTP lifecycle                            |
| ---------------------------------------------- | ----------------------------------------- |
| `capture -read file.pcap`                      | Finishes and exits after analysis         |
| `capture -read file.pcap -http 127.0.0.1:8080` | Keeps the local UI running                |
| `capture -service -http 127.0.0.1:7070`        | Upload/session service                    |
| `mcp`                                          | Stdio MCP plus an internal loopback WebUI |

Per-stream and per-decoder limits do not cap total process memory or disk. See [resource budgets](workers.md).
