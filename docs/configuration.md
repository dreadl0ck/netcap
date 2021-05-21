---
description: Adjusting framework parameters
---

# Configuration

## Command-line Flags

Each subcommand has a dedicated set of flags for configuration.

List the flag names, a short description and their default values with:

```text
$ net <subcommand> -h
```

## Environment

All default values for flags can be overriden via environment variables, by using the flag name and prefixing it with "NC\_", for example lets overwrite the **-read** flag from net capture:

```text
$ NC_READ=/home/user/traffic.pcap net capture
```

Since the provide the value via the environment, passing it via flag is no longer necessary. This is generally useful to enable or disable features globally on your system.

## Configuration File

Additionally, the configuration can be provided as a config file via the **-config** flag.

To retrieve a sane default configuration for the subcommand you want to execute, use the **-gen-config** flag and redirect the output into a file:

```text
$ net capture -gen-config > capture.conf
```

The config file will look something like this, using the **name value** syntax to set values:

```bash
...
# toggle promiscous mode for live capture
promisc true

# don't print infos to stdout
quiet false

# reassemble TCP connections
reassemble-connections true

# resolve ips to domains via the operating systems default dns resolver
reverse-dns false

# use serviceDB for device profiling
serviceDB false

# configure snaplen for live capture from interface
snaplen 1514

# print netcap package version and exit
version false

# wait for all connections to finish processing before cleanup
wait-conns true

# number of workers
workers 12

# write incomplete response
writeincomplete false
...
```

> Lines starting with \# are treated as comments, blank lines are being ignored.

Adjust the parameters of interest and pass the config file:

```text
$ net capture -config capture.conf
```

## Resolver Database

The environment variable **NC\_DATABASE\_SOURCE** can be used to overwrite the default path for the resolver databases **/usr/local/etc/netcap/db**. Read more about the resolvers package here:

{% page-ref page="resolvers.md" %}

