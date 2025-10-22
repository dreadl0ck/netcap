---
description: macOS Development Environment Setup
---

# macOS Development Setup

This guide covers setting up a complete development environment for Netcap on macOS.

## Prerequisites

### 1. Install Homebrew

If you don't have Homebrew installed:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### 2. Install Go

Install Go 1.21 or later:

```bash
brew install go
```

Verify installation:

```bash
go version
```

### 3. Install Protocol Buffers Compiler

Netcap uses Protocol Buffers for efficient data serialization. Install the `protoc` compiler:

```bash
brew install protobuf
```

Verify installation:

```bash
protoc --version
```

## Protocol Buffer Plugins

Netcap generates Protocol Buffer code for multiple languages. Install all required plugins:

### Go Plugin (gogofaster)

The `gogofaster` plugin generates optimized Go code:

```bash
go install github.com/gogo/protobuf/protoc-gen-gogofaster@latest
```

Verify installation:

```bash
which protoc-gen-gogofaster
# Should output: /Users/USERNAME/go/bin/protoc-gen-gogofaster
```

### Swift Plugin

For Swift code generation:

```bash
brew install swift-protobuf
```

Verify installation:

```bash
which protoc-gen-swift
# Should output: /opt/homebrew/bin/protoc-gen-swift
```

### JavaScript Plugin

For JavaScript code generation:

```bash
npm install -g protoc-gen-js
```

Verify installation:

```bash
which protoc-gen-js
# Should output: /Users/USERNAME/.npm-global/bin/protoc-gen-js (or similar)
```

### Built-in Plugins

The following plugins are built into `protoc` and require no separate installation:
- Python (`--python_out`)
- Java (`--java_out`)
- C++ (`--cpp_out`)
- C# (`--csharp_out`)

## Verify All Plugins

Run this command to verify all plugins are installed:

```bash
echo "✓ protoc: $(protoc --version)"
echo "✓ protoc-gen-gogofaster: $(which protoc-gen-gogofaster)"
echo "✓ protoc-gen-swift: $(which protoc-gen-swift)"
echo "✓ protoc-gen-js: $(which protoc-gen-js)"
```

## Clone and Build Netcap

### Clone the Repository

```bash
git clone https://github.com/dreadl0ck/netcap.git
cd netcap
```

### Install Zeus Build System

Netcap uses the Zeus build system:

```bash
go install github.com/dreadl0ck/zeus/cmd/zeus@latest
```

### Build Netcap

Build the project:

```bash
zeus install
```

Or build manually:

```bash
go build -o /usr/local/bin/net github.com/dreadl0ck/netcap/cmd
```

## Generate Protocol Buffers

### Development Build (Go only)

For development, you typically only need Go code:

```bash
zeus gen-proto-dev
```

Or manually:

```bash
protoc --gogofaster_out=types/. netcap.proto
```

### Release Build (All languages)

For a release build with all language bindings:

```bash
zeus gen-proto-release
```

Or manually:

```bash
mkdir -p types/{python,java,swift,cpp,csharp,js}
protoc --gogofaster_out=types/. \
       --python_out=types/python \
       --java_out=types/java \
       --swift_out=types/swift \
       --cpp_out=types/cpp \
       --csharp_out=types/csharp \
       --js_out=types/js \
       netcap.proto
```

## Environment Variables

### Go Binary Path

Ensure your Go binary directory is in your PATH. Add to `~/.zshrc` (or `~/.bash_profile`):

```bash
export PATH="$HOME/go/bin:$PATH"
```

### Netcap Configuration

Set the configuration root if needed:

```bash
export NC_CONFIG_ROOT="$HOME/.config/netcap"
```

## Troubleshooting

### protoc-gen-* not found errors

If you get errors like `protoc-gen-XXX: program not found or is not executable`:

1. Ensure the plugin is installed
2. Check if it's in your PATH:
   ```bash
   echo $PATH
   ```
3. For Go plugins, ensure `$HOME/go/bin` is in your PATH
4. For Homebrew plugins, ensure `/opt/homebrew/bin` is in your PATH

### Permission Issues

If you encounter permission errors when installing global npm packages:

```bash
# Configure npm to use a different directory
mkdir ~/.npm-global
npm config set prefix '~/.npm-global'

# Add to PATH in ~/.zshrc or ~/.bash_profile
export PATH="$HOME/.npm-global/bin:$PATH"

# Reload shell configuration
source ~/.zshrc
```

### Protocol Buffer Version Mismatch

If you encounter version mismatch errors, ensure you're using compatible versions:

```bash
# Check current versions
protoc --version
go list -m github.com/gogo/protobuf
```

## Additional Development Tools

### Optional but Recommended

Install additional tools for development:

```bash
# Code formatting
go install golang.org/x/tools/cmd/goimports@latest

# Linting
brew install golangci-lint

# Testing utilities
go install github.com/rakyll/gotest@latest

# Profiling
go install github.com/google/pprof@latest
```

## Next Steps

- Read the [Contributing Guide](contributing.md)
- Check the [Development Notes](DEVNOTES.md)
- Review the [Testing Guide](TESTING_QUICKSTART.md)
- Explore the [Architecture Documentation](internals.md)

## See Also

- [Installation Guide](installation.md) - For end-user installation
- [Quickstart](quickstart.md) - Getting started with Netcap
- [Configuration](configuration.md) - Configuration options
- [Troubleshooting](troubleshooting.md) - Common issues and solutions


