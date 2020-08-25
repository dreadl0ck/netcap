package io

import (
	"reflect"
	"testing"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

// Test if the count function works as expected
func TestCountRecords(t *testing.T) {
	num, errCount := Count("../tests/testdata/TCP.ncap.gz")
	if errCount != nil {
		t.Fatal(errCount)
	}
	if num != 3196 {
		t.Fatal("expected 3196 audit records, got: ", num)
	}
}

// Test if the init record function works as expected
func TestInitRecord(t *testing.T) {
	r := InitRecord(types.Type_NC_ICMPv6NeighborAdvertisement)
	if icmp, ok := r.(*types.ICMPv6NeighborAdvertisement); !ok {
		t.Fatal("unexpected type: ", reflect.TypeOf(r))
	} else {
		if icmp == nil {
			t.Fatal("unexpected nil")
		}
	}
}

// Benchmark how long it takes to initialize the first record in the type switch
func BenchmarkInitRecordFirst(b *testing.B) {
	var r proto.Message

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		r = InitRecord(types.Type_NC_Ethernet)
		if r == nil {
			b.Fatal("unexpected nil")
		}
	}
}

// Benchmark how long it takes to initialize the last record in the type switch
func BenchmarkInitRecordLast(b *testing.B) {
	var r proto.Message

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		r = InitRecord(types.Type_NC_Exploit)
		if r == nil {
			b.Fatal("unexpected nil")
		}
	}
}
