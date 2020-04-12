---
description: Parameter options
---

# Configuration

All default values for flags can be overriden via environment variables, by using the flag name and prefixing it with "NC\_", for example lets overwrite the **-read** flag from net capture:

```text
$ NC_READ=/home/user/traffic.pcap net capture
```

Since the provide the value via the environment, passing it via flag is no longer necessary. This is generally useful to enable or disable features globally on your system.

Additionally, the configuration can be provided as a config file:

TODO: example

## Resolver Database

An important path for netcap is the one specified by **NC\_DATABASE\_SOURCE**, as this points to the core location of the libraries for the resolvers package, which is used for the DeviceProfile encoder and possibly other custom encoders in the future. The default path is **/usr/local/etc/netcap/db** if the the env var is unset.

{% page-ref page="resolvers.md" %}

## Bash Completion

Completions for the command-line is provided via the bash-completion package which is available for most linux distros and macOS.

On macOS you can install it with brew:

```text
brew install bash-completion
```

on linux use the package manager of your distro.

Then add the completion file **cmd/net** to:

* macOS: /usr/local/etc/bash\_completion.d/
* Linux: /etc/bash\_completion.d/

and source it with:

* macOS: . /usr/local/etc/bash\_completion.d/net
* Linux: . /etc/bash\_completion.d/net

Afterwards you should receive predictions when hitting tab in the shell, for subcommands and flags. For flags that expect a path on the filesystem, path completion is available and will only display files with the expected datatype \(based on the file extension\).

