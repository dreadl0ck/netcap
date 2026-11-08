# Bash Completion

The repository ships `scripts/completions/net.bash`, a Bash completion adapter
that calls the executable's legacy `-previous`, `-current` and `-full` interface.
Completion suggestions are convenience output; `net COMMAND -h` and the
[registered command inventory](commands.md) define the executable interface.

## Installation

For Bash, source the reviewed script from your checkout:

```sh
source scripts/completions/net.bash
```

Add it to the startup configuration of the shell you actually use if desired.
System completion directories vary by distribution and Homebrew prefix; do not
assume `/usr/local` on Apple Silicon.

For Zsh's Bash compatibility layer:

```sh
autoload -U +X compinit
compinit
autoload -U +X bashcompinit
bashcompinit
source scripts/completions/net.bash
```

Verify a known current command and flag after sourcing. Historical suggestions
may include `split` or other stale interfaces; a suggested token does not make
it a registered command in v0.15.2.
