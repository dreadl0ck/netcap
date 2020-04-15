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

Adjust the parameters of interest and pass the config file:

```text
$ net capture -config capture.conf
```

## Resolver Database

The environment variable **NC\_DATABASE\_SOURCE** can be used to overwrite the default path for the resolver databases **/usr/local/etc/netcap/db**. Read more about the resolvers package here:

{% page-ref page="resolvers.md" %}

## Bash Completion

Completions for the command-line is provided via the bash-completion package which is available for most linux distros and macOS.

On macOS you can install it with brew:

```text
$ brew install bash-completion
```

on linux use the package manager of your distro.

Then add the completion file **cmd/net** to:

* macOS: /usr/local/etc/bash\_completion.d/
* Linux: /etc/bash\_completion.d/

and source it with:

* macOS: . /usr/local/etc/bash\_completion.d/net
* Linux: . /etc/bash\_completion.d/net

If you use zeus, simply execute the following in the project root to install the completion script:

```text
$ zeus install-completions
```

or move and source the file manually from the project root:

```text
$ cp cmd/net /usr/local/etc/bash_completion.d/net && . /usr/local/etc/bash_completion.d/net
```

Afterwards you should receive predictions when hitting tab in the shell, for subcommands and flags. For flags that expect a path on the filesystem, path completion is available and will only display files with the expected datatype \(based on the file extension\).

To use completion with **zsh** run the following:

```text
autoload -U +X compinit && compinit
autoload -U +X bashcompinit && bashcompinit
cp cmd/net /usr/local/etc/bash_completion.d/net && . /usr/local/etc/bash_completion.d/net
```

