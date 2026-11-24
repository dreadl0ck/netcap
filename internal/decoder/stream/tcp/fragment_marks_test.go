package tcp

import (
	"reflect"
	"testing"

	"github.com/dreadl0ck/netcap/internal/aggregate"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
)

func TestStoredReaderIndexesBoundariesAcrossColdState(t *testing.T) {
	coldTestConfig(t)
	store, err := aggregate.Open(t.TempDir(), 4096, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	decoderconfig.Instance.AggregateStore = store
	budget, err := core.NewStateBudget(0, nil)
	if err != nil {
		t.Fatal(err)
	}
	reader := &tcpStreamReader{parent: &tcpConnection{stateBudget: budget}, isClient: true}
	for _, fragment := range []*core.StreamData{
		{SkippedBytes: -1}, {RawData: []byte("GET ")}, {RawData: []byte("/x")},
		{SkippedBytes: 3, RawData: []byte("y")}, {DiscardReason: "budget", DiscardedBytes: 2}, {RawData: []byte("z"), TCPObservation: "after-rst"},
	} {
		reader.StoreData(fragment)
	}
	if reader.stored == nil {
		t.Fatal("fixture did not use stored payload")
	}
	want := []core.FragmentMark{{Index: 0}, {Index: 3, PayloadEnd: 3}, {Index: 4, PayloadEnd: 4}, {Index: 5, PayloadEnd: 4}}
	if marks, ok := reader.FragmentMarks(); !ok || !reflect.DeepEqual(marks, want) {
		t.Fatalf("marks %+v %v, want %+v", marks, ok, want)
	}
	if size, ok := reader.PayloadBytes(); !ok || size != 8 {
		t.Fatalf("payload bytes %d %v", size, ok)
	}
	if ranged, ok := core.FragmentRange(reader, 2, 3).(core.MarkedSource).FragmentMarks(); !ok || !reflect.DeepEqual(ranged, []core.FragmentMark{{Index: 1, PayloadEnd: 1}, {Index: 2, PayloadEnd: 2}}) {
		t.Fatalf("range marks %+v", ranged)
	}

	state := saveReader(reader)
	restored := &tcpStreamReader{}
	restored.marks, restored.payloadEnd, restored.indexed = state.Marks, state.PayloadEnd, state.Indexed
	restored.marksLost = !state.MarksIndexed || !validMarks(state.Marks, state.Indexed)
	restored.stored = &storedTCPReader{count: state.Count}
	if marks, ok := restored.FragmentMarks(); !ok || !reflect.DeepEqual(marks, want) {
		t.Fatalf("cold marks %+v %v", marks, ok)
	}
	if validMarks([]core.FragmentMark{{Index: 3}, {Index: 1}}, 6) || validMarks([]core.FragmentMark{{Index: 6}}, 6) {
		t.Fatal("invalid cold marks accepted")
	}

	// A fragment that bypasses StoreData must disable the index, not hide a boundary.
	if err := reader.stored.append(&core.StreamData{SkippedBytes: 4}); err != nil {
		t.Fatal(err)
	}
	if _, ok := reader.FragmentMarks(); ok {
		t.Fatal("index survived an unindexed append")
	}
	reader.dropMarks()
	if _, ok := reader.PayloadBytes(); ok {
		t.Fatal("cleared reader still reports its size")
	}
}
