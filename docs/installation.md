---
description: Setup instructions
---

# Installation

## Binary Distributions

Compiled versions for macOS, Linux and Windows are available on GitHub:

{% embed url="https://github.com/dreadl0ck/netcap/releases" caption="NETCAP GitHub Releases Page" %}

## Go Get

Installation via go get:

```text
$ go get -u github.com/dreadl0ck/netcap/...
```

## Manual Build

```text
$ go build -ldflags "-s -w" -o /usr/local/bin/net github.com/dreadl0ck/netcap/cmd
```

## Reproducible Builds via Go Modules

In order to provide stable and reproducible builds, Go modules are used to pin the versions of source code dependencies to specific versions.

Go has included support for versioned modules as proposed [here](https://golang.org/design/24301-versioned-go) since `1.11`. The initial prototype `vgo` was [announced](https://research.swtch.com/vgo) in February 2018. In July 2018, versioned modules [landed](https://groups.google.com/d/msg/golang-dev/a5PqQuBljF4/61QK4JdtBgAJ) in the main Go repository. They are used by default by the go toolchain starting from version `1.13` .

You can read about Go modules here:

{% embed url="https://github.com/golang/go/wiki/Modules" caption="" %}

{% embed url="https://blog.golang.org/using-go-modules" caption="" %}

## Development Build

To install the command-line tool:

```text
$ go build -o /usr/local/bin/net github.com/dreadl0ck/netcap/cmd
```

## Cross Compilation

To cross compile for other architectures, set the _GOARCH_ and _GOOS_ environment variables. For example to cross compile a binary for _linux amd64_:

```text
$ GOARCH=amd64 GOOS=linux go build -o bin/net github.com/dreadl0ck/netcap/cmd
```

## Homebrew

On macOS, you can install the _netcap_ command-line tool with Homebrew:

```text
$ brew tap dreadl0ck/formulas
$ brew install netcap
```

## Buildsystem

_Netcap_ uses the [zeus](https://github.com/dreadl0ck/zeus) build system, it can be found on GitHub along with installation instructions:

{% embed url="https://github.com/dreadl0ck/zeus" caption="ZEUS Build System GitHub" %}

To install the _Netcap_ and _Netlabel_ command-line tool and the library with zeus, run:

```text
$ zeus install
```

