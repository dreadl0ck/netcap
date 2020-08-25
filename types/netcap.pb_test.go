/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package types

import (
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
)

/*
 *	Test Data
 */

var auditRecord = &UDP{
	Timestamp:      time.Now().UnixNano(),      // int64
	SrcPort:        1334,                       // int32
	DstPort:        345,                        // int32
	Length:         234,                        // int32
	Checksum:       123445,                     // int32
	PayloadEntropy: 1224.123332,                // float64
	PayloadSize:    12413,                      // int32
	Payload:        []byte{0x1, 0x2, 0x3, 0x4}, // []byte
}

// serialized packet data
var auditRecordData = []byte{10, 17, 49, 53, 52, 55, 55, 54, 48, 52, 54, 54, 46, 54, 48, 52, 50, 52, 54, 16, 182, 10, 24, 217, 2, 32, 234, 1, 40, 181, 196, 7, 49, 51, 106, 190, 74, 126, 32, 147, 64, 56, 253, 96, 66, 4, 1, 2, 3, 4}

/*
 *	Tests
 */

func TestMarshal(t *testing.T) {
	data, err := proto.Marshal(auditRecord)
	if err != nil {
		t.Fatal(err)
	}

	err = proto.Unmarshal(data, auditRecord)
	if err != nil {
		t.Fatal(err)
	}

	if auditRecord.SrcPort != 1334 {
		t.Fatal("unexpected source port")
	}
}

/*
 *	Benchmarks
 */

// with default code generator
// $ go test -bench=. -v ./types
// === RUN   TestMarshal
// --- PASS: TestMarshal (0.00s)
// goos: darwin
// goarch: amd64
// pkg: github.com/dreadl0ck/netcap/types
// BenchmarkMarshal-12      	10000000	       184 ns/op	      64 B/op	       1 allocs/op
// BenchmarkUnmarshal-12    	10000000	       160 ns/op	      40 B/op	       2 allocs/op
// PASS
// ok  	github.com/dreadl0ck/netcap/types	3.830s

// with gogo code generator
// $ go test -bench=. -v ./types
// === RUN   TestMarshal
// --- PASS: TestMarshal (0.00s)
// goos: darwin
// goarch: amd64
// pkg: github.com/dreadl0ck/netcap/types
// BenchmarkMarshal-12      	20000000	        89.1 ns/op	      64 B/op	       1 allocs/op
// BenchmarkUnmarshal-12    	20000000	       110 ns/op	      40 B/op	       2 allocs/op
// PASS
// ok  	github.com/dreadl0ck/netcap/types	4.215s

func BenchmarkMarshal(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		_, err := proto.Marshal(auditRecord)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUnmarshal(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		err := proto.Unmarshal(auditRecordData, auditRecord)
		if err != nil {
			b.Fatal(err)
		}
	}
}
