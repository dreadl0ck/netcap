---
description: Adjusting framework parameters
---

# Configuration

## Command-line Flags

Each subcommand defines its own flags. Use the installed version's help for options, defaults and environment-variable names:

```sh
net capture -h
net util -h
```

## Environment

Use the variable declared by the option; names are not universally derived from flag spelling. `NC_READ` selects a capture input; `NETCAP_DBS_URL` selects a database server.

```sh
NC_READ=/path/to/traffic.pcap net capture
```

## Configuration File

Go Netcap generates and reads subcommand configuration:

```sh
net capture -gen-config > capture.conf
net capture -config capture.conf
```

Edit the generated file for the installed version instead of copying historical flag lists. Lines starting with `#` are comments; blank lines are ignored. Rust commands have their own supported configuration boundary; consult their help rather than assuming every Go utility exists.

## Resolver Database

`NC_CONFIG_ROOT` sets the parent configuration directory, not the final `dbs` directory. The default is `~/.config/netcap/dbs`.

```sh
NC_CONFIG_ROOT=/srv/netcap-config net util -download-dbs
NC_CONFIG_ROOT=/srv/netcap-config net capture -read traffic.pcap -out nc
```

Both commands use `/srv/netcap-config/dbs`. Use the same root for installation and capture. Do not merge user files or historical catalogues into the managed signed inventory.

| Setting                                          | Purpose                                                                             |
| ------------------------------------------------ | ----------------------------------------------------------------------------------- |
| `NC_CONFIG_ROOT`                                 | Parent directory for configuration and managed data                                 |
| `NETCAP_DBS_URL`                                 | Optional publisher URL override                                                     |
| `NC_DBS_APPROVALS` and `NC_DBS_APPROVALS_SHA256` | Paired private-publisher registry override; not needed for signed community updates |
| `NC_GEO_PROVIDERS`                               | DB-IP/optional GeoLite2 provider order                                              |

See [Resolvers](resolvers.md) and [Database updates](database-updates.md).
