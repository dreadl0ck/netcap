# Installation

Installation via go get:

```text
$ go get -u github.com/dreadl0ck/netcap/...
```

To install the command-line tool:

```text
$ go build -o $(go env GOPATH)/bin/netcap -i github.com/dreadl0ck/netcap/cmd
```

To cross compile for other architectures, set the _GOARCH_ and _GOOS_ environment variables. For example to cross compile a binary for _linux amd64_:

```text
$ GOARCH=amd64 GOOS=linux go build -o netcap -i github.com/dreadl0ck/netcap/cmd
```

Install the _netcap_ command-line tool with Homebrew:

```text
$ brew tap dreadl0ck/formulas
$ brew install netcap
```

#### Buildsystem

_Netcap_ uses the [zeus](https://github.com/dreadl0ck/zeus) buildsystem, it can be found on github along with installation instructions.

However, the project can easily be installed without zeus. All shell scripts needed for installation can be found in the _zeus/generated_ directory as standalone versions:

```text
zeus/generated/install-netcap.sh
zeus/generated/install-netlabel.sh
zeus/generated/install-sensor.sh
zeus/generated/install-server.sh
```

To install the _Netcap_ and _Netlabel_ command-line tool and the library with zeus, run:

```text
$ zeus install
```

### Tests

To execute the unit tests, run the following from the project root:

```text
$ go test -v -bench=. ./...
```

