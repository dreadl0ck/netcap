/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
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
