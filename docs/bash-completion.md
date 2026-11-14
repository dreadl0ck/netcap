# Shell completion

The repository includes `scripts/completions/net.bash`, a Bash completion script. Completion can suggest commands or flags your `net` build does not have. Check with `net COMMAND -h` and the [command inventory](commands.md).

## Installation

In Bash, source the script from your checkout:

```sh
source scripts/completions/net.bash
```

Add that line to your shell startup file to load it in every session. System completion directories differ between distributions and Homebrew installs; on Apple Silicon Homebrew does not use `/usr/local`.

In Zsh, use the Bash compatibility layer:

```sh
autoload -U +X compinit
compinit
autoload -U +X bashcompinit
bashcompinit
source scripts/completions/net.bash
```

After sourcing, press Tab after `net` and after a flag you know to check that it works.
