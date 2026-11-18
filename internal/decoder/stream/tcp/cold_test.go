package tcp

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/aggregate"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/dreadl0ck/netcap/internal/packetview/testutil"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func coldTestConfig(t *testing.T) {
	t.Helper()
	old := decoderconfig.Instance
	cfg := decoderconfig.DefaultConfig.Clone()
	cfg.Quiet, cfg.SaveConns, cfg.Checksum, cfg.NoOptCheck = true, false, false, false
	decoderconfig.Instance = cfg
	t.Cleanup(func() { decoderconfig.Instance = old })
}

func feedColdControl(a *reassembly.Assembler, flow gopacket.Flow, tcp *layers.TCP, at time.Time, scope string) {
	packet := gopacket.NewPacket(testutil.Serialize(tcp, gopacket.Payload(tcp.Payload)), layers.LayerTypeTCP, gopacket.Default)
	ci := gopacket.CaptureInfo{Timestamp: at, AncillaryData: []any{&packetview.Context{Scope: scope}}}
	a.AssembleWithContext(flow, packet.TransportLayer().(*layers.TCP), &context{CaptureInfo: ci, scope: scope})
}

func TestColdTCPIdleExpiryUsesStrictRestoredLastSeen(t *testing.T) {
	coldTestConfig(t)
	state, err := aggregate.Open(t.TempDir(), 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	f := newStreamFactory()
	p := reassembly.NewStreamPoolWithIdleExpiry(f)
	if err := p.EnableColdStorage(state, 2); err != nil {
		t.Fatal(err)
	}
	a := reassembly.NewAssembler(p)
	network := gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 0, 2, 1}, []byte{198, 51, 100, 1})
	for i := range 10 {
		feedColdControl(a, network, &layers.TCP{SrcPort: layers.TCPPort(40000 + i), DstPort: 80, Seq: 100, SYN: true, Window: 5000}, time.Unix(100, 0), "if:1")
	}
	if _, closed := a.FlushWithOptions(reassembly.FlushOptions{TI: time.Unix(100, 0)}); closed != 0 {
		t.Fatal("equal cutoff expired controls", closed)
	}
	feedColdControl(a, network.Reverse(), &layers.TCP{SrcPort: 80, DstPort: 40000, Seq: 500, Ack: 101, SYN: true, ACK: true, Window: 1000}, time.Unix(101, 0), "if:1")
	if _, closed := a.FlushWithOptions(reassembly.FlushOptions{TI: time.Unix(101, 0)}); closed != 18 || f.pendingPayloads != 1 {
		t.Fatal("restored last-seen deadline changed", closed, f.pendingPayloads)
	}
	if _, closed := a.FlushWithOptions(reassembly.FlushOptions{TI: time.Unix(102, 0)}); closed != 2 || f.pendingPayloads != 0 {
		t.Fatal("restored stream did not expire", closed, f.pendingPayloads)
	}
	if health := p.ControlStorageHealth(); health.ResidentConnections != 0 || health.StoredControls != 0 {
		t.Fatal("expiry retained controls", health)
	}
	p.Reset()
}

func TestColdTCPSharedPoolPreservesScopeAndConcurrentGenerations(t *testing.T) {
	coldTestConfig(t)
	state, err := aggregate.Open(t.TempDir(), 1024, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	f := newStreamFactory()
	p := reassembly.NewStreamPool(f)
	if err := p.EnableColdStorage(state, 4); err != nil {
		t.Fatal(err)
	}
	network := gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 0, 2, 1}, []byte{198, 51, 100, 1})
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Go(func() {
			a := reassembly.NewAssembler(p)
			for i := range 32 {
				feedColdControl(a, network, &layers.TCP{SrcPort: layers.TCPPort(40000 + i), DstPort: 80, Seq: 100, SYN: true, Window: 5000}, time.Unix(100, int64(i)), fmt.Sprintf("if:%d", worker))
			}
			for i := range 32 {
				feedColdControl(a, network.Reverse(), &layers.TCP{SrcPort: 80, DstPort: layers.TCPPort(40000 + i), Seq: 500, Ack: 101, SYN: true, ACK: true, Window: 5000}, time.Unix(101, int64(i)), fmt.Sprintf("if:%d", worker))
			}
		})
	}
	wg.Wait()
	health := p.ControlStorageHealth()
	if health.StoredControls+int64(health.ResidentConnections) != 256 || f.pendingPayloads != 256 {
		t.Fatal("scope or shared-pool generations collapsed", health, f.pendingPayloads)
	}
	a := reassembly.NewAssembler(p)
	if closed := a.FlushAll(); closed != 256 || f.pendingPayloads != 0 {
		t.Fatal("shared pool omitted controls", closed, f.pendingPayloads)
	}
	p.Reset()
}

func TestColdTCPRestoreCorruptionCancelsBackingStore(t *testing.T) {
	coldTestConfig(t)
	var cancelled atomic.Bool
	state, err := aggregate.Open(t.TempDir(), 1, func() { cancelled.Store(true) })
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	f := newStreamFactory()
	p := reassembly.NewStreamPool(f)
	if err := p.EnableColdStorage(state, 1); err != nil {
		t.Fatal(err)
	}
	a := reassembly.NewAssembler(p)
	network := gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 0, 2, 1}, []byte{198, 51, 100, 1})
	for i := range 2 {
		feedColdControl(a, network, &layers.TCP{SrcPort: layers.TCPPort(40000 + i), DstPort: 80, Seq: 100, SYN: true, Window: 5000}, time.Unix(100, int64(i)), "if:1")
	}
	if err := state.Do(func(tx *aggregate.Tx) error {
		target := ""
		if err := tx.Each("tcp/control/", func(key string, _ []byte) error {
			if strings.Contains(key, "/states/") {
				target = key
			}
			return nil
		}); err != nil {
			return err
		}
		if target == "" {
			t.Fatal("fixture did not spill a control state")
		}
		return tx.Put(target, []byte("not a control snapshot"))
	}); err != nil {
		t.Fatal(err)
	}
	feedColdControl(a, network.Reverse(), &layers.TCP{SrcPort: 80, DstPort: 40000, Seq: 500, Ack: 101, SYN: true, ACK: true, Window: 5000}, time.Unix(101, 0), "if:1")
	if state.Error() == nil || !cancelled.Load() {
		t.Fatal("corrupt control state silently created a new stream", state.Error())
	}
	if f.pendingPayloads != 2 {
		t.Fatal("failed restore changed logical admission", f.pendingPayloads)
	}
	p.Reset()
}

func TestColdTCPSnapshotPreservesValidationAndReservations(t *testing.T) {
	coldTestConfig(t)
	store, err := aggregate.Open(t.TempDir(), 4096, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	decoderconfig.Instance.AggregateStore = store
	f := newStreamFactory()
	budget, err := core.NewStateBudget(8192, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.stateBudget = budget
	network := gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 0, 2, 1}, []byte{198, 51, 100, 1})
	transport := gopacket.NewFlow(layers.EndpointTCPPort, []byte{0x9c, 0x40}, []byte{0, 80})
	ctx := &context{CaptureInfo: gopacket.CaptureInfo{Timestamp: time.Unix(100, 123)}, scope: "if:3/vlan:7"}
	c := f.New(network, transport, ctx).(*tcpConnection)
	syn := &layers.TCP{SYN: true, Seq: 0xffffffff, Window: 5000, Options: []layers.TCPOption{{OptionType: layers.TCPOptionKindMSS, OptionData: []byte{5, 0xb4}}, {OptionType: layers.TCPOptionKindWindowScale, OptionData: []byte{3}}}}
	if !c.Accept(syn, reassembly.TCPDirClientToServer, -1) {
		t.Fatal("fixture SYN rejected")
	}
	reader := c.newTCPStreamReader(true)
	reader.stored = &storedTCPReader{state: store, prefix: "tcp/payload/fixture/", budget: budget}
	for _, payload := range []string{"GET ", "/x"} {
		if err := reader.stored.append(&core.StreamData{RawData: []byte(payload)}); err != nil {
			t.Fatal(err)
		}
	}
	reader.CloseData()
	c.client = reader
	wire, err := c.SaveColdState()
	if err != nil {
		t.Fatal(err)
	}
	c.ColdSuspended()
	if budget.Health().RetainedBytes != 0 || f.pendingPayloads != 1 {
		t.Fatal("suspension changed logical admission", budget.Health(), f.pendingPayloads)
	}
	stream, err := f.RestoreColdState(wire, true)
	if err != nil {
		t.Fatal(err)
	}
	restored := stream.(*tcpConnection)
	got, err := restored.SaveColdState()
	if err != nil || !bytes.Equal(got, wire) {
		t.Fatal("control snapshot changed", string(got), string(wire), err)
	}
	copyBudget, err := core.NewStateBudget(6, nil)
	if err != nil {
		t.Fatal(err)
	}
	prefix, err := core.ReadBudgetedSourcePrefix(readerFragments(restored.client), 16<<10, copyBudget)
	if err != nil || string(prefix) != "GET /x" || cap(prefix) != 6 {
		t.Fatalf("cold prefix=%q capacity=%d: %v", prefix, cap(prefix), err)
	}
	copyBudget.Release(int64(cap(prefix)))
	if health := copyBudget.Health(); health.RetainedBytes != 0 || health.PeakBytes != 6 || health.Exceeded {
		t.Fatalf("unexpected prefix credits: %+v", health)
	}
	synack := &layers.TCP{SYN: true, ACK: true, Seq: 500, Ack: 0, Window: 1000}
	if !restored.Accept(synack, reassembly.TCPDirServerToClient, -1) {
		t.Fatal("restored SYN-ACK rejected")
	}
	ack := &layers.TCP{ACK: true, Seq: 0, Ack: 501, Window: 5000}
	if !restored.Accept(ack, reassembly.TCPDirClientToServer, 0) || restored.initStage != 3 || restored.roleSource != "syn" || restored.networkScope != "if:3/vlan:7" {
		t.Fatal("handshake/role/sequence wrap lost", restored.initStage, restored.roleSource)
	}
	restored.ReassemblyRetired()
	if budget.Health().RetainedBytes != 0 || f.pendingPayloads != 0 {
		t.Fatal("retirement leaked reservations", budget.Health(), f.pendingPayloads)
	}
}

func TestColdTCPPoolBoundsSYNStatesAndPreservesLateControls(t *testing.T) {
	coldTestConfig(t)
	state, err := aggregate.Open(t.TempDir(), 2048, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	f := newStreamFactory()
	p := reassembly.NewStreamPoolWithIdleExpiry(f)
	if err := p.EnableColdStorage(state, 2); err != nil {
		t.Fatal(err)
	}
	a := reassembly.NewAssembler(p)
	feed := func(flow gopacket.Flow, tcp *layers.TCP, at time.Time) {
		packet := gopacket.NewPacket(testutil.Serialize(tcp), layers.LayerTypeTCP, gopacket.Default)
		a.AssembleWithContext(flow, packet.TransportLayer().(*layers.TCP), &context{CaptureInfo: gopacket.CaptureInfo{Timestamp: at}})
	}
	network := gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 0, 2, 1}, []byte{198, 51, 100, 1})
	for i := range 100 {
		feed(network, &layers.TCP{SrcPort: layers.TCPPort(40000 + i), DstPort: 80, Seq: uint32(100 + i), SYN: true, Window: 5000}, time.Unix(100, int64(i)))
	}
	health := p.ControlStorageHealth()
	if health.ResidentControls > 2 || health.ResidentConnections > 2 || health.StoredControls != 98 || f.pendingPayloads != 100 {
		t.Fatal("SYN states escaped backing store", health, f.pendingPayloads)
	}
	feed(network.Reverse(), &layers.TCP{SrcPort: 80, DstPort: 40000, Seq: 500, Ack: 101, SYN: true, ACK: true, Window: 1000}, time.Unix(101, 0))
	feed(network, &layers.TCP{SrcPort: 40000, DstPort: 80, Seq: 101, Ack: 501, ACK: true, Window: 5000}, time.Unix(101, 1))
	if state.Error() != nil || f.pendingPayloads != 100 {
		t.Fatal("late control restoration changed logical streams", state.Error(), f.pendingPayloads)
	}
	if closed := a.FlushAll(); closed != 100 || f.pendingPayloads != 0 {
		t.Fatal("EOF omitted cold controls", closed, f.pendingPayloads)
	}
	if closed := a.FlushAll(); closed != 100 || f.pendingPayloads != 0 {
		t.Fatal("repeated flush changed retained controls", closed, f.pendingPayloads)
	}
	a.FlushWithOptions(reassembly.FlushOptions{TC: time.Unix(200, 0)})
	if health := p.ControlStorageHealth(); health.ResidentConnections != 0 || health.StoredControls != 0 {
		t.Fatal("closed cold states survived expiry", health)
	}
	p.Reset()
	if f.pendingPayloads != 0 {
		t.Fatal("reset retired a logical stream twice", f.pendingPayloads)
	}
}
