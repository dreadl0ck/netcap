package flow

import (
	"context"
	"math"
	"testing"
)

func TestSeriesClippingConservationAndDirectionalCoverage(t *testing.T) {
	d := NewDataset(10)
	record := flowFixture("long", "192.0.2.1", "198.51.100.1", 600000000, 60, 1)
	record.BytesClientToServer, record.BytesServerToClient = 100000000, 500000000
	if err := d.Add(record, 0); err != nil {
		t.Fatal(err)
	}
	q := Query{StartNs: 15e9, EndNs: 45e9, GroupBy: "srcIP", SortBy: "bytes", Limit: 100, BucketNs: 10e9}
	r, err := d.Query(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if r.Groups[0].Bytes != 600000000 || r.Groups[0].BytePercent != 100 || len(r.Series) != 3 {
		t.Fatalf("raw counts must remain whole observations: %+v", r)
	}
	var total float64
	for _, bin := range r.Series {
		total += bin.EstimatedBytes
		if bin.EstimatedBytes != 100000000 || bin.EstimatedBitsPerSecond != 80000000 || !bin.DirectionalComplete || math.Abs(bin.EstimatedClientBytes+bin.EstimatedServerBytes-bin.EstimatedBytes) > 0.001 {
			t.Fatalf("incorrect interpolated bin: %+v", bin)
		}
	}
	if total != 300000000 || r.Statistics.DurationNs.Median != 60e9 {
		t.Fatalf("window estimate/statistics: %+v", r)
	}
	q.WindowMode = "contained"
	r, err = d.Query(context.Background(), q)
	if err != nil || r.Matched != 0 {
		t.Fatal("overlap silently used for contained query")
	}
	q.WindowMode = "start"
	q.StartNs = 0
	r, err = d.Query(context.Background(), q)
	if err != nil || r.Matched != 1 {
		t.Fatal("start-window selection failed")
	}
	q.WindowMode = "end"
	r, err = d.Query(context.Background(), q)
	if err != nil || r.Matched != 0 {
		t.Fatal("end-window selection failed")
	}
}

func TestSeriesBoundsAndZeroDuration(t *testing.T) {
	d := NewDataset(2)
	record := flowFixture("instant", "192.0.2.1", "198.51.100.1", 42, 0, 1)
	record.TimestampFirst, record.TimestampLast = 10, 10
	if err := d.Add(record, 0); err != nil {
		t.Fatal(err)
	}
	q := Query{StartNs: 0, EndNs: 10, GroupBy: "srcIP", SortBy: "bytes", Limit: 1, BucketNs: 3}
	r, err := d.Query(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Series) != 4 || r.Series[3].EstimatedBytes != 42 || r.Series[3].DirectionalComplete {
		t.Fatal("instantaneous observation lost or unknown direction presented as complete")
	}
	q.StartNs, q.EndNs = math.MinInt64, math.MaxInt64
	if _, err := d.Query(context.Background(), q); err == nil {
		t.Fatal("overflowed bin range accepted")
	}
	q.StartNs, q.EndNs, q.BucketNs = 0, 5000, 1
	if _, err := d.Query(context.Background(), q); err == nil {
		t.Fatal("bin budget ignored")
	}
}
