package tcp

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/aggregate"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestStoredTCPMaterializationBudgets(t *testing.T) {
	for _, mode := range []string{"state", "payload", "loaded-append", "missing-fragment", "completion-missing-fragment", "unlimited"} {
		t.Run(mode, func(t *testing.T) {
			cancelled := false
			state, err := aggregate.Open(t.TempDir(), 1024, func() { cancelled = true })
			if err != nil {
				t.Fatal(err)
			}
			defer state.Close()
			limit := int64(0)
			if mode == "state" {
				limit = 1
			}
			budget, err := core.NewStateBudget(limit, func() { cancelled = true })
			if err != nil {
				t.Fatal(err)
			}
			s := &storedTCPReader{state: state, prefix: "test/tcp/", budget: budget}
			missing := mode == "missing-fragment" || mode == "completion-missing-fragment"
			if mode == "completion-missing-fragment" {
				s.completionBudget = budget.CompletionView()
			}
			if mode == "payload" || mode == "loaded-append" {
				s.payloadBudget = &retainedPayloadBudget{limit: 4, onExceeded: func() { cancelled = true }}
			}
			for range 2 {
				if err := s.append(&core.StreamData{RawData: []byte("data")}); err != nil {
					t.Fatal(err)
				}
			}
			if missing {
				if err := state.Do(func(tx *aggregate.Tx) error { return tx.Delete(s.prefix + "0000000000000001") }); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "loaded-append" {
				s.loaded = true
				err = s.append(&core.StreamData{RawData: []byte("oversized")})
			} else {
				before := state.Health().DiskReads
				_, err = s.read()
				if mode == "state" && state.Health().DiskReads-before != 1 {
					t.Fatal("state refusal read ahead into later backing rows")
				}
			}
			if mode == "unlimited" {
				if err != nil || cancelled || budget.Health().RetainedBytes == 0 {
					t.Fatal("unlimited materialization failed", err, budget.Health())
				}
			} else {
				if err == nil || !cancelled {
					t.Fatal("materialization did not fail capture", err, cancelled, state.Health())
				}
				if missing {
					if state.Error() == nil || errors.Is(err, core.ErrCompletionStateBudget) {
						t.Fatal("integrity failure did not fail storage")
					}
				} else {
					if state.Error() != nil {
						t.Fatal("resource pressure poisoned unrelated storage", state.Error())
					}
					if err := state.Do(func(tx *aggregate.Tx) error { return tx.Put("independent/output", []byte("available")) }); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "state" && !errors.Is(err, core.ErrStreamStateBudget) {
					t.Fatal("lost state budget cause", err)
				}
				if budget.Health().RetainedBytes != 0 || (s.payloadBudget != nil && s.payloadBudget.used.Load() != 0) {
					t.Fatal("failed materialization leaked credits", budget.Health())
				}
			}
			_ = s.clear()
			if budget.Health().RetainedBytes != 0 {
				t.Fatal("cleanup leaked materialization credits", budget.Health())
			}
		})
	}
}

func TestStoredTCPReaderPayloadDoesNotAccumulateBeforeCompletion(t *testing.T) {
	coldTestConfig(t)
	state, err := aggregate.Open(t.TempDir(), 65536, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	decoderconfig.Instance.AggregateStore = state
	f := newStreamFactory()
	network := gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 0, 2, 1}, []byte{198, 51, 100, 1})
	transport := gopacket.NewFlow(layers.EndpointTCPPort, []byte{0x9c, 0x40}, []byte{0, 80})
	ctx := &context{CaptureInfo: gopacket.CaptureInfo{Timestamp: time.Unix(100, 0)}, scope: "if:1"}
	c := f.New(network, transport, ctx).(*tcpConnection)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	payload := bytes.Repeat([]byte{0xa5}, 1024)
	for range 32768 {
		c.feedData(reassembly.TCPDirClientToServer, payload, ctx)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	heap := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	r := c.client.(*tcpStreamReader)
	if heap > 8<<20 || len(r.data) != 0 || r.stored == nil || r.stored.count != 32768 || state.Health().PeakBytes > 65536 {
		t.Fatal("TCP payload remained resident", heap, state.Health())
	}
	t.Logf("TCP payload=33554432 retainedHeapDelta=%d database=%d", heap, state.Health().DatabaseBytes)
	c.recordRetentionDiscard(reassembly.TCPDirClientToServer, 3, ctx)
	c.recordRetentionDiscard(reassembly.TCPDirClientToServer, 5, ctx)
	data := r.DataSlice()
	if len(data) != 32769 || !bytes.Equal(data[0].Raw(), payload) {
		t.Fatal("stored TCP reader changed fragments", len(data))
	}
	last := data[len(data)-1]
	if discarded := last.(*core.StreamData).DiscardedBytes; discarded != 8 {
		t.Fatal("mutable discard marker update was lost", discarded)
	}
	c.releaseResources()
	c.ReassemblyRetired()
	f.wg.Wait()
}

func TestStoredTCPReadersSuspendRestoreAndRetireWithoutTasks(t *testing.T) {
	coldTestConfig(t)
	state, err := aggregate.Open(t.TempDir(), 1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	decoderconfig.Instance.AggregateStore = state
	f := newStreamFactory()
	p := reassembly.NewStreamPool(f)
	if err := p.EnableColdStorage(state, 2); err != nil {
		t.Fatal(err)
	}
	a := reassembly.NewAssembler(p)
	network := gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 0, 2, 1}, []byte{198, 51, 100, 1})
	for i := range 100 {
		tcp := &layers.TCP{SrcPort: layers.TCPPort(40000 + i), DstPort: 9999, Seq: 100, SYN: true, Window: 5000}
		feedColdControl(a, network, tcp, time.Unix(100, int64(i)), "if:1")
		feedColdControl(a, network.Reverse(), &layers.TCP{SrcPort: 9999, DstPort: layers.TCPPort(40000 + i), Seq: 500, Ack: 101, SYN: true, ACK: true, Window: 5000}, time.Unix(100, int64(i)+100), "if:1")
		tcp.SYN, tcp.ACK, tcp.Seq = false, true, 101
		tcp.Ack = 501
		tcp.Payload = []byte(fmt.Sprintf("opaque-%d", i))
		feedColdControl(a, network, tcp, time.Unix(101, int64(i)), "if:1")
	}
	health := p.ControlStorageHealth()
	if health.StoredControls != 98 || health.ResidentConnections != 2 || len(f.readerSnapshot()) != 4 {
		t.Fatal("payload readers/tasks escaped backing", health, len(f.readerSnapshot()))
	}
	p.Reset()
	f.wg.Wait()
	if f.numActive != 0 || f.pendingPayloads != 0 {
		t.Fatal("cold reader retirement leaked counters", f.numActive, f.pendingPayloads)
	}
}
