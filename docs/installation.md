---
description: Setup instructions
---

# Installation

## Binary Distributions

Compiled versions for macOS, Linux and Windows are available on GitHub:

{% embed url="https://github.com/dreadl0ck/netcap/releases" caption="NETCAP GitHub Releases Page" %}

Linux archives built by `zeus/scripts/build-{ubuntu,alpine}-docker.sh` include
`net` and a private `lib/` runtime. Keep that directory together: `net` launches
`lib/net.bin` with the bundled ELF loader and libraries, including nDPI,
libprotoident and libtrace for DPI builds. It does not install system libraries.
Use the libc archive on Debian/Ubuntu and the musl archive on Alpine.

For offline analysis, `net capture --read traffic.pcap --out nc` exits after
flushing records. Add `--http localhost:8080` to keep the WebUI running.
`net dump --read nc/HTTP.ncap.gz --json --sort-time` provides stable capture-time
ordering using temporary files and bounded-memory sorting; capture files retain
decoder emission order.

The default per-decoder buffer is 64 KiB (`--membuf-size` overrides it).
Missing optional `nmap-service-probes` no longer prevents Service startup:
built-in parsers recognize SSH, HTTP, SMTP and FTP greetings. External probes
remain optional; `--download-dbs` does not install Nmap's catalogue.

Windows identity extraction covers visible Kerberos principals, NTLM Type 3
identities, LDAP directory attributes, SAMR query classes 1/6/7/8/21, and LSA
lookup request names/SIDs. SAMR/LSA stubs require NDR32; SMB2 SAMR/LSA pipes are
supported through CREATE, WRITE, READ and PIPE_TRANSCEIVE. `IdentityStatus`
records incomplete, encrypted and unsupported RPC results; LSA translated
responses, NDR64 and SMB1 pipe transports are not decoded.

HTTP preserves the wire request target and supports requests in either TCP
direction. `ReassemblyStatus` qualifies unpaired records after capture loss and
incomplete request bodies. SMTP LOGIN/PLAIN exchanges appear in `Secret`; `Notes`
distinguishes success, rejection and an unknown result. Successful IMAP STARTTLS,
SMTP STARTTLS and POP3 STLS end plaintext parsing.

DeviceProfile retains a deterministic sample of at most 4,096 contacts and a
65,536-key deduplication set. `ContactObservations` counts observations;
`ContactCountLowerBound` and `ContactsTruncated` qualify cardinality after limits.
Extracted artifacts use SHA-256 basenames with preserved extensions; source names
and URLs remain in File metadata.

`NETCAP_MTA_ROOT=/path/to/captures go test -tags nodpi ./internal/collector -run
TestMTAReportRegressions` replays the checksum-pinned 2019-12-25 and 2021-12-08
captures without extracting artifacts. The tests cover post-gap HTTP requests,
asymmetric-MAC flow totals, SMTP AUTH and banner-only POP3.

## Go Get

Installation via go get:

```text
$ go get -u github.com/dreadl0ck/netcap/...
```

## Manual Build

```text
$ go build -ldflags "-s -w" -o /usr/local/bin/net github.com/dreadl0ck/netcap/cmd/net
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
$ go build -o /usr/local/bin/net github.com/dreadl0ck/netcap/cmd/net
```

## Cross Compilation

To cross compile for other architectures, set the _GOARCH_ and _GOOS_ environment variables. For example to cross compile a binary for _linux amd64_:

```text
$ GOARCH=amd64 GOOS=linux go build -o bin/net github.com/dreadl0ck/netcap/cmd/net
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
