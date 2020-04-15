---
description: Tab completion for the shell
---

# Bash Completion

## Installation

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

