# Shell Completion Setup

Netcap supports shell completion for bash, zsh, fish, and PowerShell using urfave/cli v3.

## ZSH Setup (macOS default)

Add the following to your `~/.zshrc`:

```bash
# Enable zsh completion system
autoload -Uz compinit
compinit

# Netcap completion
source <(net completion zsh)
```

Then reload your shell:
```bash
source ~/.zshrc
```

## Bash Setup

Add to your `~/.bashrc` or `~/.bash_profile`:

```bash
# Netcap completion
source <(net completion bash)
```

Then reload your shell:
```bash
source ~/.bashrc
```

## Fish Setup

Generate and install completion file:

```bash
net completion fish > ~/.config/fish/completions/net.fish
```

The completion will be automatically loaded in new fish shells.

## PowerShell Setup

Generate the completion script:

```powershell
net completion pwsh > net.ps1
```

Add to your PowerShell profile (open with `code $profile` or `notepad $profile`):

```powershell
& C:\path\to\net.ps1
```

## Verifying Completion Works

After enabling completion, test it:

```bash
# Autocomplete subcommands
net <TAB>

# Autocomplete flags for a subcommand
net capture --<TAB>

# Autocomplete with partial input
net ca<TAB>  # Should complete to "capture"
```

## Available Shells

To see which shells are supported, run:

```bash
net completion --help
```

Available shells: `bash`, `zsh`, `fish`, `pwsh`

## Features

Shell completion provides:

- **Subcommand completion**: All 9 subcommands
- **Flag completion**: All 265+ flags across all subcommands
- **Context-aware**: Flags only shown for relevant subcommands
- **Environment variable hints**: Shows `[$NC_*]` in help text
- **Dynamic generation**: Completion reflects current build

## Troubleshooting

**ZSH completion not working:**
- Ensure `compinit` is called in your `.zshrc`
- Try running `compinit` manually in your current shell
- Check that `net` binary is in your `$PATH`

**Bash completion not working:**
- Install `bash-completion` package if not already installed
- Ensure `.bashrc` is sourced in your shell

**No completions showing:**
- Verify the binary is accessible: `which net`
- Test manual completion generation: `net completion zsh`
- Check shell configuration is sourced: `echo $SHELL`

