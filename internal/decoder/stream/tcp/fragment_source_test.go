package tcp

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"testing"

	"github.com/dreadl0ck/netcap/internal/aggregate"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
)

func TestFirstSourceFragmentChargesCopyBeforeAdmission(t *testing.T) {
	client := core.SliceSource{&core.StreamData{RawData: []byte("client")}}
	server := core.SliceSource{&core.StreamData{RawData: []byte("server")}}
	budget, err := core.NewStateBudget(11, nil)
	if err != nil {
		t.Fatal(err)
	}
	var credit int64
	working := budget.CompletionView()
	if data, _, _, err := firstSourceFragment(client, false, working, &credit); err != nil || string(data) != "client" {
		t.Fatalf("first prefix: %q, %v", data, err)
	}
	if data, _, _, err := firstSourceFragment(server, false, working, &credit); data != nil || !errors.Is(err, core.ErrCompletionStateBudget) {
		t.Fatalf("second prefix exceeded budget: %q, %v", data, err)
	}
	if health := budget.Health(); health.Exceeded || health.RetainedBytes != 6 || health.CompletionRejectedBytes != 6 {
		t.Fatalf("unexpected completion budget: %+v", health)
	}
	working.Release(credit)
	if health := budget.Health(); health.RetainedBytes != 0 {
		t.Fatalf("prefix reservation leaked: %+v", health)
	}
}

func TestResidentFirstFragmentFitsSmallProbeBudget(t *testing.T) {
	raw := make([]byte, 4096)
	copy(raw, "GET /fixture HTTP/1.1\r\n")
	reader := &tcpStreamReader{data: core.DataFragments{&core.StreamData{RawData: raw}}}
	budget, err := core.NewStateBudget(1, nil)
	if err != nil {
		t.Fatal(err)
	}
	var credit int64
	got, _, _, err := firstSourceFragment(readerFragments(reader), false, budget, &credit)
	if err != nil || !bytes.Equal(got, raw) || credit != 0 || budget.Health().PeakBytes != 0 {
		t.Fatalf("resident probe bytes=%d credit=%d: %v", len(got), credit, err)
	}
}

func TestBackedTCPPrefixFitsSmallCopyBudget(t *testing.T) {
	state, err := aggregate.Open(t.TempDir(), 4096, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	readBudget, err := core.NewStateBudget(8192, nil)
	if err != nil {
		t.Fatal(err)
	}
	stored := &storedTCPReader{state: state, prefix: "tcp/prefix/", budget: readBudget}
	for _, payload := range []string{"GET ", "/x"} {
		if err := stored.append(&core.StreamData{RawData: []byte(payload)}); err != nil {
			t.Fatal(err)
		}
	}
	reader := &tcpStreamReader{stored: stored, isClient: true}
	copyBudget, err := core.NewStateBudget(6, nil)
	if err != nil {
		t.Fatal(err)
	}
	prefix, err := core.ReadBudgetedSourcePrefix(core.FragmentRange(reader, 0, reader.Count()), 16<<10, copyBudget)
	if err != nil || string(prefix) != "GET /x" || cap(prefix) != 6 || stored.loaded {
		t.Fatalf("backed prefix=%q capacity=%d loaded=%t: %v", prefix, cap(prefix), stored.loaded, err)
	}
	copyBudget.Release(int64(cap(prefix)))
	if copyHealth, readHealth := copyBudget.Health(), readBudget.Health(); copyHealth.RetainedBytes != 0 || copyHealth.Exceeded || readHealth.RetainedBytes != 0 {
		t.Fatalf("copy credits=%+v read credits=%+v", copyHealth, readHealth)
	}
}

func TestStoredTCPSourceIsRestartableWithinOneFragmentBudget(t *testing.T) {
	state, err := aggregate.Open(t.TempDir(), 4096, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	budget, err := core.NewStateBudget(8192, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload := &retainedPayloadBudget{limit: 1024}
	source := &storedTCPReader{state: state, prefix: "tcp/source/", budget: budget, payloadBudget: payload}
	for i := range 4096 {
		if err := source.append(&core.StreamData{RawData: bytes.Repeat([]byte{byte(i)}, 1024)}); err != nil {
			t.Fatal(err)
		}
	}
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	var retained int64
	for range 2 {
		index := 0
		err := source.Walk(func(fragment core.DataFragment) bool {
			if !bytes.Equal(fragment.Raw(), bytes.Repeat([]byte{byte(index)}, 1024)) {
				t.Fatal("fragment changed", index)
			}
			index++
			if index == 2048 || index == 4096 {
				runtime.GC()
				var now runtime.MemStats
				runtime.ReadMemStats(&now)
				retained = max(retained, int64(now.HeapAlloc)-int64(before.HeapAlloc))
			}
			if err := state.Do(func(tx *aggregate.Tx) error { return tx.Put("independent", []byte("available")) }); err != nil {
				t.Fatal(err)
			}
			return true
		})
		if err != nil || index != 4096 || source.Count() != 4096 {
			t.Fatal("source replay incomplete", index, err)
		}
		if budget.Health().RetainedBytes != 0 || payload.used.Load() != 0 || source.loaded {
			t.Fatal("source retained decoded payload", budget.Health())
		}
	}
	reads := state.Health().DiskReads
	seen := 0
	if err := source.WalkRange(2047, 1, func(fragment core.DataFragment) bool {
		seen++
		if fragment.Raw()[0] != 255 {
			t.Fatal("range started at wrong fragment")
		}
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if seen != 1 || state.Health().DiskReads-reads > 1 {
		t.Fatal("stored range replay scanned a prefix", seen, state.Health().DiskReads-reads)
	}
	if budget.Health().PeakBytes > 8192 || payload.peak.Load() > 1024 {
		t.Fatal("iteration exceeded fragment bounds")
	}
	if retained > 2<<20 {
		t.Fatal("iteration retained conversation payload", retained)
	}
	t.Logf("payload bytes=4194304 retained heap delta=%d state credit peak=%d", retained, budget.Health().PeakBytes)
}

func TestStoredTCPBatchRangeAndEarlyStop(t *testing.T) {
	state, err := aggregate.Open(t.TempDir(), 4096, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	budget, err := core.NewStateBudget(0, nil)
	if err != nil {
		t.Fatal(err)
	}
	source := &storedTCPReader{state: state, prefix: "tcp/batch/", budget: budget}
	for i := range 2 * aggregate.BatchRows {
		if err := source.append(&core.StreamData{RawData: []byte{byte(i)}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, stopAfter := range []int{3, aggregate.BatchRows + 1} {
		seen := 0
		err := source.WalkRange(7, aggregate.BatchRows+1, func(fragment core.DataFragment) bool {
			if !bytes.Equal(fragment.Raw(), []byte{byte(7 + seen)}) {
				t.Fatalf("wrong fragment at index %d", 7+seen)
			}
			seen++
			return seen < stopAfter
		})
		if err != nil || seen != stopAfter || budget.Health().RetainedBytes != 0 {
			t.Fatalf("range retained state or stopped incorrectly: seen=%d err=%v", seen, err)
		}
	}
}

func TestBackedRoleCorrectionDoesNotLoadConversation(t *testing.T) {
	state, err := aggregate.Open(t.TempDir(), 1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	budget, _ := core.NewStateBudget(8192, nil)
	stored := &storedTCPReader{state: state, prefix: "tcp/roles/", budget: budget, payloadBudget: &retainedPayloadBudget{limit: 1024}}
	for range 32 {
		if err := stored.append(&core.StreamData{RawData: bytes.Repeat([]byte{1}, 1024), Dir: reassembly.TCPDirClientToServer}); err != nil {
			t.Fatal(err)
		}
	}
	connection := new(tcpConnection)
	client := &tcpStreamReader{parent: connection, isClient: true, stored: stored}
	server := &tcpStreamReader{parent: connection, isClient: false}
	connection.client, connection.server = client, server
	connection.flipRoles()
	count := 0
	if err := readerFragments(connection.server).Walk(func(fragment core.DataFragment) bool {
		if fragment.Direction() != reassembly.TCPDirServerToClient {
			t.Fatal("stored role correction was lost")
		}
		count++
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if count != 32 || stored.loaded || budget.Health().RetainedBytes != 0 {
		t.Fatal("role correction materialized payload", count, budget.Health())
	}
}

func TestStoredTCPSourceStopsAndReleasesCredits(t *testing.T) {
	state, err := aggregate.Open(t.TempDir(), 1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	budget, _ := core.NewStateBudget(8192, nil)
	source := &storedTCPReader{state: state, prefix: "tcp/source/", budget: budget, payloadBudget: &retainedPayloadBudget{limit: 8192}}
	for range 2 {
		if err := source.append(&core.StreamData{RawData: []byte("body")}); err != nil {
			t.Fatal(err)
		}
	}
	if err := source.Walk(func(core.DataFragment) bool { return false }); err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("callback panic did not propagate")
			}
		}()
		_ = source.Walk(func(core.DataFragment) bool { panic("control") })
	}()
	if budget.Health().RetainedBytes != 0 || source.payloadBudget.used.Load() != 0 {
		t.Fatal("abandoned walk leaked credits")
	}
	if err := state.Do(func(tx *aggregate.Tx) error { return tx.DeleteKey(fmt.Sprintf("%s%016x", source.prefix, 1)) }); err != nil {
		t.Fatal(err)
	}
	if err := source.Walk(func(core.DataFragment) bool { return true }); err == nil || state.Error() == nil {
		t.Fatal("missing source row was accepted")
	}
}
