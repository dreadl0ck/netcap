package collector

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/decoder/config"
)

// Admission-path benchmarks.
//
// Measured: everything submitPacket does per packet — dispatchMu lock/unlock,
// the disposal defer, the stopped/empty guards, getSymmetricWorkerIndex, the
// c.wg.Add(1) registration, the worker channel send, the admittedPackets
// bookkeeping and the FlushEvery modulo plus its control broadcast to every
// worker channel (all of which the candidate added under the global lock).
//
// Not measured: packet parsing (packets are pre-built and eagerly decoded in
// setup), reassembly, decoding and audit record writing. Worker channels are
// constructed directly via rawPacketCollector and drained by trivial consumers
// that only count and release the WaitGroup, so a real decoding worker never
// runs. Numbers are therefore admission cost only, not end-to-end throughput.
//
// Pitfall: whenever a live consumer goroutine exists, whichever side is slower
// parks and the other pays a goready per packet. That wake-up costs more than
// the lock and shifts with producer speed, so BenchmarkCollectorAdmission and
// its lock-free twin BenchmarkCollectorAdmissionChannelSend report realistic
// throughput but not a clean lock price. BenchmarkAdmissionLockOverhead removes
// the consumer entirely to price the lock.

const (
	admissionPacketPool = 512 // pre-built packets, cycled; keeps memory bounded
	admissionQueueDepth = 256 // per-worker channel capacity
)

// admissionPackets builds fully decoded Ethernet/IPv4/TCP packets with varying
// source ports so flow sharding spreads them over all worker channels.
func admissionPackets(tb testing.TB, n int) []gopacket.Packet {
	tb.Helper()

	payload := gopacket.Payload(bytes.Repeat([]byte{0xa5}, 64))
	ts := time.Unix(1600000000, 0)
	packets := make([]gopacket.Packet, n)

	for i := range packets {
		eth := &layers.Ethernet{
			SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11},
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := &layers.IPv4{
			Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP,
			SrcIP: net.IPv4(10, 0, 0, 1), DstIP: net.IPv4(10, 0, 0, 2),
		}
		tcp := &layers.TCP{SrcPort: layers.TCPPort(30000 + i), DstPort: 80, ACK: true, Seq: 1, Window: 4096}
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			tb.Fatal(err)
		}

		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
			eth, ip, tcp, payload); err != nil {
			tb.Fatal(err)
		}

		// gopacket.Default is eager: all layers are parsed here, not in the loop.
		data := buf.Bytes()
		p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		p.Metadata().CaptureInfo = gopacket.CaptureInfo{
			Timestamp: ts.Add(time.Duration(i) * time.Millisecond), Length: len(data), CaptureLength: len(data),
		}
		packets[i] = p
	}

	return packets
}

type admissionHarness struct {
	c        *Collector
	packets  []gopacket.Packet
	data     atomic.Int64 // data packets observed by the drains
	controls atomic.Int64 // FlushEvery control broadcasts observed by the drains
	drainWG  sync.WaitGroup
}

// admissionCollector builds a Collector with real worker channels but no real
// decoding workers.
func admissionCollector(workers, capacity, flushEvery int) *Collector {
	c := rawPacketCollector(workers, capacity, gopacket.Default)
	if flushEvery > 0 {
		c.config.ReassembleConnections = true
		c.config.DecoderConfig = &config.Config{FlushEvery: flushEvery}
	}

	return c
}

// newAdmissionHarness wires real worker channels to trivial drain goroutines.
func newAdmissionHarness(tb testing.TB, workers, flushEvery int) *admissionHarness {
	c := admissionCollector(workers, admissionQueueDepth, flushEvery)
	h := &admissionHarness{c: c, packets: admissionPackets(tb, admissionPacketPool)}

	for _, w := range c.workers {
		h.drainWG.Add(1)

		go func(in chan gopacket.Packet) {
			defer h.drainWG.Done()

			for p := range in {
				if _, ok := p.(*workerControl); ok {
					h.controls.Add(1)
					continue
				}

				h.data.Add(1)
				c.wg.Done() // admission registered this packet with c.wg
			}
		}(w)
	}

	return h
}

func (h *admissionHarness) stop() {
	for _, w := range h.c.workers {
		close(w)
	}
	h.drainWG.Wait()
}

// run drives submit for exactly b.N packets, from one or many producer
// goroutines, and verifies the drains actually saw them.
func (h *admissionHarness) run(b *testing.B, multiProducer bool, flushEvery int, submit func(*Collector, gopacket.Packet)) {
	pool := len(h.packets)

	b.ResetTimer()

	if multiProducer {
		var seed atomic.Int64

		b.RunParallel(func(pb *testing.PB) {
			i := int(seed.Add(1)*31) % pool
			for pb.Next() {
				submit(h.c, h.packets[i])
				if i++; i == pool {
					i = 0
				}
			}
		})
	} else {
		for i := 0; i < b.N; i++ {
			submit(h.c, h.packets[i%pool])
		}
	}

	b.StopTimer()
	h.stop()

	if got := h.data.Load(); got != int64(b.N) {
		b.Fatalf("admitted %d packets, want %d", got, b.N)
	}

	// admittedPackets is incremented under dispatchMu, so the broadcast count is
	// exact even with multiple producers.
	wantControls := 0
	if flushEvery > 0 {
		wantControls = b.N / flushEvery * h.c.numWorkers
	}

	if got := h.controls.Load(); got != int64(wantControls) {
		b.Fatalf("control broadcasts = %d, want %d", got, wantControls)
	}
}

func admitLocked(c *Collector, p gopacket.Packet) {
	c.handlePacket(p)
}

// admitLockFree mirrors the pre-mutex admission path: shard, register, send.
// No dispatchMu, no admittedPackets counter, no FlushEvery modulo check. The
// delta against admitLocked is the per-packet cost the candidate introduced.
func admitLockFree(c *Collector, p gopacket.Packet) {
	idx := c.getSymmetricWorkerIndex(p)
	c.wg.Add(1)
	c.workers[idx] <- p
	atomic.AddInt64(&c.current, 1)
}

func benchmarkAdmission(b *testing.B, flushes []int, submit func(*Collector, gopacket.Packet)) {
	for _, workers := range []int{1, 4, 8} {
		for _, flush := range flushes {
			for _, multi := range []bool{false, true} {
				producers := "single-producer"
				if multi {
					producers = "multi-producer"
				}

				b.Run(fmt.Sprintf("workers=%d/flush=%d/%s", workers, flush, producers), func(b *testing.B) {
					newAdmissionHarness(b, workers, flush).run(b, multi, flush, submit)
				})
			}
		}
	}
}

// BenchmarkCollectorAdmission measures Collector.submitPacket, including the
// global dispatchMu taken on every packet.
func BenchmarkCollectorAdmission(b *testing.B) {
	benchmarkAdmission(b, []int{0, 64}, admitLocked)
}

// BenchmarkCollectorAdmissionChannelSend is the lock-free reference: the same
// harness and packets, but a bare sharded channel send. Compare ns/op with
// BenchmarkCollectorAdmission/flush=0 to price the mutex.
func BenchmarkCollectorAdmissionChannelSend(b *testing.B) {
	benchmarkAdmission(b, []int{0}, admitLockFree)
}

// isolatedQueueDepth/isolatedRound: no consumer runs during the timed loop, so
// channels must hold a whole round. Worst case is a single worker taking every
// data packet plus every control: round + round/flush < depth. Memory stays at
// depth*workers pointers (512KB at 8 workers).
const (
	isolatedQueueDepth = 8192
	isolatedRound      = 2048
)

// benchmarkAdmissionIsolated prices the admission logic without any scheduler
// interaction: there is no receiver goroutine, so every send is a plain write
// into a non-full buffer, identical in both variants. Channels are drained in
// bounded rounds with the timer stopped. The locked/lockfree delta is therefore
// dispatchMu, the timeout select, the disposal defer and the admittedPackets
// plus FlushEvery bookkeeping - not channel handoff.
func benchmarkAdmissionIsolated(b *testing.B, workers, flushEvery int, submit func(*Collector, gopacket.Packet)) {
	c := admissionCollector(workers, isolatedQueueDepth, flushEvery)
	packets := admissionPackets(b, admissionPacketPool)

	var data, controls int

	drain := func() {
		for _, w := range c.workers {
			for len(w) > 0 {
				if _, ok := (<-w).(*workerControl); ok {
					controls++
					continue
				}

				data++

				c.wg.Done()
			}
		}
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		submit(c, packets[i%admissionPacketPool])

		if (i+1)%isolatedRound == 0 {
			b.StopTimer()
			drain()
			b.StartTimer()
		}
	}

	b.StopTimer()
	drain()

	if data != b.N {
		b.Fatalf("admitted %d packets, want %d", data, b.N)
	}

	wantControls := 0
	if flushEvery > 0 {
		wantControls = b.N / flushEvery * workers
	}

	if controls != wantControls {
		b.Fatalf("control broadcasts = %d, want %d", controls, wantControls)
	}
}

// BenchmarkAdmissionLockOverhead quantifies the per-packet cost the mutex-based
// admission adds over a bare sharded channel send. Single producer: the lock is
// uncontended there, which is the real pcap/live case.
func BenchmarkAdmissionLockOverhead(b *testing.B) {
	variants := []struct {
		name   string
		flush  int
		submit func(*Collector, gopacket.Packet)
	}{
		{"lockfree", 0, admitLockFree},
		{"locked", 0, admitLocked},
		{"locked-flush64", 64, admitLocked},
	}

	for _, workers := range []int{1, 8} {
		for _, v := range variants {
			b.Run(fmt.Sprintf("workers=%d/%s", workers, v.name), func(b *testing.B) {
				benchmarkAdmissionIsolated(b, workers, v.flush, v.submit)
			})
		}
	}
}

// TestAdmissionBenchmarkHarness keeps the harness honest under `go test`.
func TestAdmissionBenchmarkHarness(t *testing.T) {
	h := newAdmissionHarness(t, 4, 2)
	packets := h.packets[:8]

	for _, p := range packets {
		if !h.c.handlePacket(p) {
			t.Fatal("packet was not admitted")
		}
	}

	h.stop()

	if got := h.data.Load(); got != int64(len(packets)) {
		t.Fatalf("drained %d packets, want %d", got, len(packets))
	}

	if got, want := h.controls.Load(), int64(len(packets)/2*h.c.numWorkers); got != want {
		t.Fatalf("control broadcasts = %d, want %d", got, want)
	}

	// Sharding must actually spread packets, otherwise multi-worker runs would
	// only ever exercise a single channel.
	shards := make(map[int]bool)
	for _, p := range h.packets[:64] {
		shards[h.c.getSymmetricWorkerIndex(p)] = true
	}

	if len(shards) != h.c.numWorkers {
		t.Fatalf("packets hit %d of %d worker shards", len(shards), h.c.numWorkers)
	}
}
