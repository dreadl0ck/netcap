---
description: Netcap has tests for its core functionality
---

# Unit tests

## Prerequisites

The tests operate on a dump file that is not in the repository.

You can download it with:

```text
$ zeus download-test-pcap
```

which will basically just invoke:

```text
wget https://weberblog.net/wp-content/uploads/2020/02/The-Ultimate-PCAP.7z
```

Now unpack the file and move it to the tests folder in the project root.

## Unit Tests

To execute the unit tests, run the following from the project root:

```text
$ go test -v ./...
```

## Benchmarks

Run the benchmarks using:

```text
$ go test -v -bench=. ./...
```

## Race Detection Tests

Run the tests with race detection enabled:

```text
$ go test -race -v ./...
```

