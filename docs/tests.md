---
description: Netcap has tests for its core functionality
---

# Unit Tests

## Prerequisites

Some of the tests operate on a dump file that is not in the repository.

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

Unit tests have been implemented for parts of the core functionality. Currently there are basic tests for reading pcap data from files and traffic live from an interface, as well as tests and benchmarks for common utility functions, such progress displaying and time conversions.

The tests and benchmarks can be executed from the repository root by executing the following from the project root:

```text
$ go test -v ./...
=== RUN   TestCountRecords
--- PASS: TestCountRecords (0.18s)
=== RUN   TestReader
--- PASS: TestReader (0.01s)
=== RUN   TestWriter
--- PASS: TestWriter (0.06s)
PASS
ok      github.com/dreadl0ck/netcap    0.862s
?       github.com/dreadl0ck/netcap/cmd    [no test files]
?       github.com/dreadl0ck/netcap/cmd/agent    [no test files]
?       github.com/dreadl0ck/netcap/cmd/capture    [no test files]
?       github.com/dreadl0ck/netcap/cmd/collect    [no test files]
?       github.com/dreadl0ck/netcap/cmd/dump    [no test files]
?       github.com/dreadl0ck/netcap/cmd/export    [no test files]
?       github.com/dreadl0ck/netcap/cmd/label    [no test files]
?       github.com/dreadl0ck/netcap/cmd/proxy    [no test files]
?       github.com/dreadl0ck/netcap/cmd/split    [no test files]
?       github.com/dreadl0ck/netcap/cmd/transform    [no test files]
?       github.com/dreadl0ck/netcap/cmd/util    [no test files]
=== RUN   TestCollectPCA
done in 2.595847118s
--- PASS: TestCollectPCAP (2.60s)
PASS
ok      github.com/dreadl0ck/netcap/collector    3.242s
=== RUN   TestCorruptedWriter
    TestCorruptedWriter: delimited_test.go:46: Put record returned expected error: BAD
--- PASS: TestCorruptedWriter (0.00s)
=== RUN   TestGoodWriter
--- PASS: TestGoodWriter (0.00s)
=== RUN   TestCorruptedReader
    TestCorruptedReader: delimited_test.go:87: Next record returned expected error: unexpected EOF
--- PASS: TestCorruptedReader (0.00s)
=== RUN   TestGoodReader
--- PASS: TestGoodReader (0.00s)
=== RUN   TestRoundTrip
    TestRoundTrip: delimited_test.go:136: After writing: buffer="\x04Some\x02of\x04what\x01a\x04fool\x06thinks\x05often\bremains." len=42
--- PASS: TestRoundTrip (0.00s)
PASS
ok      github.com/dreadl0ck/netcap/delimited    0.526s
?       github.com/dreadl0ck/netcap/dpi    [no test files]
?       github.com/dreadl0ck/netcap/decoder    [no test files]
?       github.com/dreadl0ck/netcap/io    [no test files]
?       github.com/dreadl0ck/netcap/label    [no test files]
?       github.com/dreadl0ck/netcap/maltego    [no test files]
?       github.com/dreadl0ck/netcap/metrics    [no test files]
?       github.com/dreadl0ck/netcap/resolvers    [no test files]
=== RUN   TestMarshal
--- PASS: TestMarshal (0.00s)
PASS
ok      github.com/dreadl0ck/netcap/types    0.668s
=== RUN   TestTimeToString
--- PASS: TestTimeToString (0.00s)
=== RUN   TestStringToTime
--- PASS: TestStringToTime (0.00s)
PASS
ok      github.com/dreadl0ck/netcap/utils    0.932s
```

## Benchmarks

Run the benchmarks using:

```text
$ go test -bench=. ./... | grep -E "Bench|pkg"
pkg: github.com/dreadl0ck/netcap/collector
BenchmarkReadPcapNG-12                 1265539           844 ns/op        1249 B/op           1 allocs/op
BenchmarkReadPcapNGZeroCopy-12         2028283           640 ns/op           0 B/op           0 allocs/op
BenchmarkReadPcap-12                   7557667           137 ns/op         106 B/op           1 allocs/op
pkg: github.com/dreadl0ck/netcap/types
BenchmarkMarshal-12           9817819           110 ns/op          64 B/op           1 allocs/op
BenchmarkUnmarshal-12         8703766           134 ns/op          40 B/op           2 allocs/op
pkg: github.com/dreadl0ck/netcap/utils
BenchmarkTimeToStringOld-12                5283726           229 ns/op          64 B/op           4 allocs/op
BenchmarkTimeToString-12                   8273997           136 ns/op          80 B/op           3 allocs/op
BenchmarkStringToTime-12                   8842005           137 ns/op          32 B/op           1 allocs/op
BenchmarkStringToTimeFieldsFunc-12         6809409           185 ns/op          32 B/op           1 allocs/op
BenchmarkProgressOld-12                   54425902            21.0 ns/op           0 B/op           0 allocs/op
BenchmarkProgress-12                      23389420            45.9 ns/op          16 B/op           2 allocs/op
```

## Race Detection Tests

Run the tests with race detection enabled:

```text
$ go test -race -v ./...
```

