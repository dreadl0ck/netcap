package packet

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/dpi"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

type connectionTestWriter struct {
	netio.AuditRecordWriter
	mu      sync.Mutex
	records []*types.Connection
	gate    func()
}

func (w *connectionTestWriter) Write(msg proto.Message) error {
	if w.gate != nil {
		w.gate()
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.records = append(w.records, proto.Clone(msg).(*types.Connection))
	return nil
}

func (w *connectionTestWriter) Flush() error                { return nil }
func (w *connectionTestWriter) Close(int64) (string, int64) { return "", 0 }

func connectionConcurrencySetup(t *testing.T) {
	t.Helper()
	if dpi.IsEnabled() {
		t.Fatal("connection concurrency tests require DPI disabled")
	}
	oldConf, oldInstance := conf, decoderconfig.Instance
	conf = &decoderconfig.Config{Quiet: true, NumStreamWorkers: 1, StreamBufferSize: 1}
	decoderconfig.Instance = conf
	ResetConnections()
	t.Cleanup(func() {
		ResetConnections()
		conf, decoderconfig.Instance = oldConf, oldInstance
	})
}

func connectionAwait(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for connection synchronization")
		}
		runtime.Gosched()
	}
}

func connectionDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	connectionAwait(t, func() bool {
		select {
		case <-done:
			return true
		default:
			return false
		}
	})
}

func TestConnectionConcurrentCreation(t *testing.T) {
	connectionConcurrencySetup(t)
	p := connectionBenchmarkPackets(t, 1)[0]
	p.TransportLayer().(*layers.TCP).Window = 0 // Avoid the order-dependent moving average.
	const workers, repetitions = 32, 64
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range repetitions {
				handlePacket(p)
			}
		}()
	}
	close(start)
	wg.Wait()
	if conns.Size() != 1 {
		t.Fatalf("created %d connections, want 1", conns.Size())
	}
	for _, c := range conns.Items {
		n := int32(workers * repetitions)
		if c.NumPackets != n || c.TotalSize != n*int32(p.Metadata().Length) ||
			c.AppPayloadSize != n*int32(len(p.TransportLayer().LayerPayload())) ||
			c.BytesClientToServer != int64(c.TotalSize) || c.BytesServerToClient != 0 ||
			c.packetsClientToServer != int64(n) || c.packetsServerToClient != 0 ||
			c.TimestampFirst != p.Metadata().Timestamp.UnixNano() || c.TimestampLast != c.TimestampFirst ||
			c.NumACKFlags != n || c.NumPSHFlags != n || c.NumSYNFlags+c.NumFINFlags+c.NumRSTFlags+c.NumURGFlags+c.NumECEFlags+c.NumCWRFlags+c.NumNSFlags != 0 {
			t.Fatalf("incorrect aggregate: %s", c.Connection)
		}
	}
}

func TestConnectionConcurrentFlowsAndFlush(t *testing.T) {
	connectionConcurrencySetup(t)
	flows := make([][]gopacket.Packet, 16)
	for i, base := range connectionBenchmarkPackets(t, len(flows)) {
		for j := range 32 {
			p := gopacket.NewPacket(base.Data(), layers.LayerTypeEthernet, gopacket.Default)
			p.Metadata().CaptureInfo = base.Metadata().CaptureInfo
			p.Metadata().Timestamp = p.Metadata().Timestamp.Add(time.Duration(32-j) * time.Millisecond)
			tcp := p.TransportLayer().(*layers.TCP)
			tcp.Window, tcp.FIN, tcp.RST = 0, j%3 == 0, j%5 == 0
			if j%2 != 0 {
				eth, ip := p.LinkLayer().(*layers.Ethernet), p.NetworkLayer().(*layers.IPv4)
				eth.SrcMAC, eth.DstMAC = eth.DstMAC, eth.SrcMAC
				ip.SrcIP, ip.DstIP = ip.DstIP, ip.SrcIP
				tcp.SrcPort, tcp.DstPort = tcp.DstPort, tcp.SrcPort
			}
			flows[i] = append(flows[i], p)
		}
	}
	// Keep per-flow order identical; only inter-flow scheduling differs.
	want := make(map[string]*types.Connection)
	for _, flow := range flows {
		for _, p := range flow {
			handlePacket(p)
		}
	}
	for key, c := range conns.Items {
		want[key] = proto.Clone(c.Connection).(*types.Connection)
	}
	ResetConnections()
	var wg sync.WaitGroup
	for _, flow := range flows {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, p := range flow {
				handlePacket(p)
			}
		}()
	}
	wg.Wait()
	if conns.Size() != len(want) {
		t.Fatalf("got %d flows, want %d", conns.Size(), len(want))
	}
	for key, c := range conns.Items {
		if !proto.Equal(c.Connection, want[key]) {
			t.Fatalf("flow %s differs from serial oracle: got %s want %s", key, c.Connection, want[key])
		}
	}
	// Use stable direction for repeated flushes: existing writeConn swaps bytes
	// in place when an earlier reverse packet changed SrcIP.
	ResetConnections()
	w := &connectionTestWriter{}
	d := &Decoder{Writer: w}
	packets := connectionBenchmarkPackets(t, len(flows))
	for _, p := range packets {
		p.TransportLayer().(*layers.TCP).Window = 0
		handlePacket(p)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				handlePacket(p)
			}
		}()
	}
	var flushed int64
	for range 20 {
		flushed += connectionDecoder.FlushState(d)
	}
	wg.Wait()
	flushed += connectionDecoder.FlushState(d)
	if int64(len(w.records)) != flushed || atomic.LoadInt64(&d.NumRecordsWritten) != flushed {
		t.Fatalf("flush accounting: records=%d callback=%d decoder=%d", len(w.records), flushed, d.NumRecordsWritten)
	}
	for i, c := range w.records {
		if c.NumPackets < 1 || c.NumPackets > 101 || c.TotalSize != c.NumPackets*int32(packets[0].Metadata().Length) ||
			c.BytesClientToServer != int64(c.TotalSize) || c.BytesServerToClient != 0 || c.PacketsClientToServer != int64(c.NumPackets) ||
			c.NumACKFlags != c.NumPackets || c.NumPSHFlags != c.NumPackets || (i >= len(w.records)-len(packets) && c.NumPackets != 101) {
			t.Fatalf("inconsistent snapshot: %s", c)
		}
	}
}

func TestConnectionBlockedUpdateAndReset(t *testing.T) {
	connectionConcurrencySetup(t)
	packets := connectionBenchmarkPackets(t, 2)
	handlePacket(packets[0])
	var c *connection
	for _, c = range conns.Items {
	}
	c.Lock()
	locked := true
	defer func() {
		if locked {
			c.Unlock()
		}
	}()
	updated := make(chan struct{})
	go func() { handlePacket(packets[0]); close(updated) }()
	connectionAwait(t, func() bool {
		if conns.operations.TryLock() {
			conns.operations.Unlock()
			return false
		}
		return true
	})
	independent := make(chan struct{})
	go func() { handlePacket(packets[1]); handlePacket(packets[1]); close(independent) }()
	connectionDone(t, independent)
	reset := make(chan struct{})
	go func() { ResetConnections(); close(reset) }()
	connectionAwait(t, func() bool {
		if conns.operations.TryRLock() {
			conns.operations.RUnlock()
			return false
		}
		return true
	})
	select {
	case <-reset:
		t.Fatal("reset passed an admitted update")
	default:
	}
	c.Unlock()
	locked = false
	connectionDone(t, updated)
	connectionDone(t, reset)
	if c.NumPackets != 2 || conns.Size() != 0 {
		t.Fatalf("update/reset lost ordering: packets=%d size=%d", c.NumPackets, conns.Size())
	}
}

type connectionAdmittedPacket struct {
	gopacket.Packet
	admitted chan struct{}
}

func (p connectionAdmittedPacket) LinkLayer() gopacket.LinkLayer {
	close(p.admitted)
	return p.Packet.LinkLayer()
}

func TestConnectionFinalFlushExclusion(t *testing.T) {
	connectionConcurrencySetup(t)
	p := connectionBenchmarkPackets(t, 1)[0]
	handlePacket(p)
	entered, release := make(chan struct{}, 2), make(chan struct{}, 2)
	defer close(release)
	w := &connectionTestWriter{gate: func() { entered <- struct{}{}; <-release }}
	d := &Decoder{Writer: w}
	periodic := make(chan struct{})
	go func() { connectionDecoder.FlushState(d); close(periodic) }()
	connectionDone(t, entered)
	if conns.operations.TryLock() {
		conns.operations.Unlock()
		t.Error("periodic flush released its read gate before writing finished")
	}
	admitted, updated := make(chan struct{}), make(chan struct{})
	go func() { handlePacket(connectionAdmittedPacket{p, admitted}); close(updated) }()
	connectionDone(t, admitted)
	final := make(chan struct{})
	go func() {
		if err := connectionDecoder.DeInit(d); err != nil {
			t.Error(err)
		}
		close(final)
	}()
	connectionAwait(t, func() bool {
		if conns.operations.TryRLock() {
			conns.operations.RUnlock()
			return false
		}
		return true
	})
	select {
	case <-final:
		t.Fatal("final flush passed admitted readers")
	default:
	}
	release <- struct{}{}
	connectionDone(t, periodic)
	connectionDone(t, updated)
	connectionDone(t, entered)
	if conns.operations.TryRLock() {
		conns.operations.RUnlock()
		t.Error("final flush released exclusive gate before workers finished")
	}
	release <- struct{}{}
	connectionDone(t, final)
	if len(w.records) != 2 || w.records[0].NumPackets != 1 || w.records[1].NumPackets != 2 || d.NumRecordsWritten != 2 {
		t.Fatalf("final flush accounting: records=%v count=%d", w.records, d.NumRecordsWritten)
	}
}
