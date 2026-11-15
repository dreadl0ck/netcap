package collector

import (
	"encoding/binary"
	"fmt"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func writeUniqueUDPFlows(tb testing.TB, path string, count int) {
	tb.Helper()
	f, err := os.Create(path)
	if err != nil {
		tb.Fatal(err)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		tb.Fatal(err)
	}
	frame := make([]byte, 62)
	copy(frame, []byte{2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 8, 0})
	ip := frame[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(ip[2:], 48)
	copy(ip[12:], []byte{192, 0, 2, 1})
	copy(ip[16:], []byte{198, 51, 100, 1})
	udp := frame[34:42]
	binary.BigEndian.PutUint16(udp[2:], 9999)
	binary.BigEndian.PutUint16(udp[4:], 28)
	copy(frame[42:], []byte("synthetic flow bytes"))
	for i := range count {
		binary.BigEndian.PutUint16(udp, uint16(1024+i%60000))
		ip[14], ip[15] = byte(i/60000), byte(i/60000+1)
		if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1700000000, int64(i)*1000), CaptureLength: len(frame), Length: len(frame)}, frame); err != nil {
			tb.Fatal(err)
		}
	}
}

func TestSYNScanHeapProfile(t *testing.T) {
	profile := os.Getenv("NETCAP_SYN_HEAP")
	if profile == "" {
		t.Skip("set NETCAP_SYN_HEAP to profile retained SYN-only state")
	}
	count := 50000
	if value := os.Getenv("NETCAP_SYN_FLOWS"); value != "" {
		var err error
		count, err = strconv.Atoi(value)
		if err != nil || count < 1 || count > 1000000 {
			t.Fatal("NETCAP_SYN_FLOWS must be between 1 and 1000000")
		}
	}
	cfg := ultimateCaptureConfig(t.TempDir(), 2, 0)
	cfg.NetworkDetection = true
	if value := os.Getenv("NETCAP_AGGREGATE_STATE_BYTES"); value != "" {
		limit, err := strconv.ParseInt(value, 10, 64)
		if err != nil || limit < 0 {
			t.Fatal("NETCAP_AGGREGATE_STATE_BYTES must be a nonnegative integer")
		}
		cfg.DecoderConfig.MaxAggregateStateBytes = limit
	}
	c := New(cfg)
	if err := c.Init(); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := range count {
		frame := make([]byte, 54)
		copy(frame, []byte{2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 8, 0})
		ip := frame[14:34]
		ip[0], ip[8], ip[9] = 0x45, 64, 6
		binary.BigEndian.PutUint16(ip[2:], 40)
		copy(ip[12:], []byte{192, 0, 2, 1})
		copy(ip[16:], []byte{198, 51, 100, 1})
		ip[14], ip[15] = byte(i/60000), byte(i/60000+1)
		tcp := frame[34:]
		binary.BigEndian.PutUint16(tcp, uint16(i%60000+1024))
		binary.BigEndian.PutUint16(tcp[2:], 80)
		tcp[12], tcp[13] = 0x50, 2
		p := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
		p.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Unix(1700000000, int64(i)*1000), CaptureLength: len(frame), Length: len(frame)}
		if !c.handlePacket(p) {
			t.Fatal("packet admission stopped")
		}
	}
	c.wg.Wait()
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	t.Logf("SYN-only retained heap: %d bytes for %d flows (%.1f bytes/flow)", after.HeapAlloc-before.HeapAlloc, count, float64(after.HeapAlloc-before.HeapAlloc)/float64(count))
	if state := c.config.DecoderConfig.AggregateStore; state != nil {
		health := state.Health()
		t.Logf("aggregate store: %+v", health)
		if health.PeakBytes > health.LimitBytes || count > 4096 && health.DiskWrites == 0 {
			t.Fatal("aggregate state did not spill within its cache bound", health)
		}
	}
	f, err := os.Create(profile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pprof.WriteHeapProfile(f); err != nil {
		t.Fatal(err)
	}
}

func TestUDPUniqueFlowAccounting(t *testing.T) {
	const count = 1500
	input, out := filepath.Join(t.TempDir(), "udp.pcap"), t.TempDir()
	writeUniqueUDPFlows(t, input, count)
	ultimateRun(t, input, out, 2, 0)
	counts, _ := ultimateRecords(t, out)
	if counts["Connection"] != count || counts["Service"] != 1 {
		t.Fatal("unique UDP flows lost", counts)
	}
	r, err := netio.Open(filepath.Join(out, "Service.ncap"), 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.ReadHeader(); err != nil {
		t.Fatal(err)
	}
	var record types.Service
	if err := r.Next(&record); err != nil {
		t.Fatal(err)
	}
	if len(record.Flows) != count {
		t.Fatalf("service retained %d/%d flow references", len(record.Flows), count)
	}
}

func BenchmarkUDPUniqueFlows(b *testing.B) {
	for _, count := range []int{5000, 10000, 20000, 40000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			input := filepath.Join(b.TempDir(), "udp.pcap")
			writeUniqueUDPFlows(b, input, count)
			b.ResetTimer()
			for range b.N {
				cfg := ultimateCaptureConfig(b.TempDir(), 2, 0)
				cfg.NetworkDetection, cfg.FlowExports = true, true
				c := New(cfg)
				if err := c.CollectPcap(input); err != nil {
					b.Fatal(err)
				}
				if got := c.GetNumPackets(); got != int64(count) {
					b.Fatalf("processed %d; want %d", got, count)
				}
			}
			b.ReportMetric(float64(count), "flows/op")
		})
	}
}
