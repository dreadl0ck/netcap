package packet

import (
	"bytes"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/aggregate"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/dpi"
	"github.com/dreadl0ck/netcap/internal/linkaudit"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/dreadl0ck/netcap/internal/packetview/testutil"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type hostTestWriter struct {
	netio.AuditRecordWriter
	mu      sync.Mutex
	records []*types.Host
}

func (w *hostTestWriter) Write(record proto.Message) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.records = append(w.records, proto.Clone(record).(*types.Host))
	return nil
}

func compareStoredHosts(t *testing.T, initDPI func()) {
	t.Helper()
	previous, previousInstance := conf, decoderconfig.Instance
	conf = &decoderconfig.Config{Quiet: true}
	decoderconfig.Instance = conf
	t.Cleanup(func() {
		conf.AggregateStore = nil
		ResetHosts()
		conf, decoderconfig.Instance = previous, previousInstance
	})
	packets := connectionBenchmarkPackets(t, 300)
	base := gopacket.NewPacket(packets[0].Data(), layers.LayerTypeEthernet, gopacket.Default)
	base.Metadata().CaptureInfo = packets[0].Metadata().CaptureInfo
	ip := base.NetworkLayer().(*layers.IPv4)
	tcp := base.TransportLayer().(*layers.TCP)
	ip.SrcIP, ip.DstIP = ip.DstIP, ip.SrcIP
	tcp.SrcPort, tcp.DstPort = tcp.DstPort, tcp.SrcPort
	late := serializedEvidencePacket(t, base, base.Metadata().Timestamp.Add(-time.Second))
	packets = append(packets, late)
	run := func(store *aggregate.Store) []*types.Host {
		conf.AggregateStore = nil
		ResetHosts()
		conf.AggregateStore = store
		initDPI()
		w := &hostTestWriter{}
		d := &Decoder{Writer: w}
		for pass := 0; pass < 2; pass++ {
			for _, p := range packets {
				hostDecoder.Handler(p)
			}
			if count := hostDecoder.FlushState(d); count != 301 {
				t.Fatalf("hosts=%d, want 301", count)
			}
		}
		if err := hostDecoder.DeInit(d); err != nil {
			t.Fatal(err)
		}
		// Stable sort keeps each host's snapshot sequence together.
		sort.SliceStable(w.records, func(i, j int) bool { return w.records[i].Addr < w.records[j].Addr })
		return w.records
	}
	want := run(nil)
	if dpi.IsEnabled() {
		classified := false
		for _, host := range want {
			if len(host.Protocols) > 0 {
				classified = true
				break
			}
		}
		if !classified {
			t.Fatal("native DPI fixture produced no classifications")
		}
	}
	for _, limit := range []int64{1, 2048, 1 << 20} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			store, err := aggregate.Open(t.TempDir(), limit, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			defer func() { conf.AggregateStore = nil }()
			got := run(store)
			if len(got) != len(want) {
				t.Fatalf("records=%d, want %d", len(got), len(want))
			}
			for i := range got {
				if !proto.Equal(got[i], want[i]) {
					t.Fatalf("host %d differs\ngot: %s\nwant: %s", i, got[i], want[i])
				}
			}
			if h := store.Health(); h.PeakBytes > limit || h.DiskWrites == 0 {
				t.Fatal(h)
			}
			if hosts.Size() != 301 {
				t.Fatal("disk-backed host count differs")
			}
			ResetHosts()
			if hosts.Size() != 0 {
				t.Fatal("ResetHosts retained persisted profiles")
			}
		})
	}
}

func TestStoredHostsMatchMemoryWithPortChurnAndLatePackets(t *testing.T) {
	if dpi.IsEnabled() {
		t.Fatal("host comparison requires a disabled DPI baseline")
	}
	compareStoredHosts(t, func() {})
}

func TestStoredHostsPreserveNativeDPI(t *testing.T) {
	dpi.InitWithConfig("", dpi.RuntimeConfig{Workers: 1})
	defer dpi.Destroy()
	if !dpi.IsEnabled() {
		t.Skip("native DPI is not compiled in")
	}
	compareStoredHosts(t, func() { dpi.Destroy(); dpi.InitWithConfig("", dpi.RuntimeConfig{Workers: 1}) })
}

func TestStoredDeferredPacketPreservesViewAndCaptureMetadata(t *testing.T) {
	for _, ethernet := range []bool{false, true} {
		wire := testutil.TCP(false, false, 10, 0, "A", "owned packet bytes")
		base := layers.LayerTypeIPv4
		if ethernet {
			wire, base = testutil.Ethernet(wire), layers.LayerTypeEthernet
		}
		p := gopacket.NewPacket(wire, base, gopacket.NoCopy)
		context := &packetview.Context{Scope: "if:7/vxlan:\xff", Status: "inner", Packets: []*types.CapturePacketRef{{TimestampUnavailable: true}}}
		p.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Unix(0, 123), CaptureLength: len(wire), Length: len(wire) + 4, InterfaceIndex: 7, AncillaryData: []any{context, packetview.CaptureInterface(42), &linkaudit.FrameCheck{Known: true, Present: true}}}
		encoded, err := marshalBufferedPacket(bufferDPIPacket(p))
		if err != nil {
			t.Fatal(err)
		}
		stored, err := unmarshalBufferedPacket(encoded)
		if err != nil {
			t.Fatal(err)
		}
		decoded := stored.packet()
		if decoded.ErrorLayer() != nil || !bytes.Equal(decoded.Data(), wire) || decoded.Layers()[0].LayerType() != base || packetview.Scope(decoded) != context.Scope || !packetview.TimeUnavailable(decoded.Metadata().CaptureInfo) || packetview.LogicalInterface(decoded.Metadata().CaptureInfo) != 42 || decoded.Metadata().Timestamp.UnixNano() != 123 || decoded.Metadata().CaptureLength != len(wire) || decoded.Metadata().Length != len(wire)+4 {
			t.Fatalf("persisted deferred packet lost its view: %v %+v", decoded, decoded.Metadata())
		}
		if check := linkaudit.FrameCheckInfo(decoded.Metadata().CaptureInfo); !check.Known || !check.Present {
			t.Fatal(check)
		}
		if _, err = unmarshalBufferedPacket(append(encoded, 0)); err == nil {
			t.Fatal("trailing deferred state accepted")
		}
	}
}

func TestStoredHostNamesDoNotGrowTheHotRecord(t *testing.T) {
	store, err := aggregate.Open(t.TempDir(), 2048, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	prefix := "host/fields/fixture/"
	host := &types.Host{Addr: "192.0.2.1", NumPackets: 1000, Bytes: 64000}
	base, err := proto.Marshal(host)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		host.SNIs = map[string]int64{fmt.Sprintf("name-%04d.example", i): 2, "repeated.example": 1}
		host.Ja4Fingerprints = []string{"shared fingerprint"}
		host.Devices = []string{"shared device"}
		if err = store.Do(func(tx *aggregate.Tx) error { return putHostProperties(tx, prefix, host) }); err != nil {
			t.Fatal(err)
		}
		wire, err := proto.Marshal(host)
		if err != nil || !bytes.Equal(wire, base) {
			t.Fatal("growing attributes stayed in the hot host record", err)
		}
	}
	if err = store.Do(func(tx *aggregate.Tx) error { return loadHostFields(tx, prefix, host) }); err != nil {
		t.Fatal(err)
	}
	if len(host.SNIs) != 1001 || host.SNIs["repeated.example"] != 1000 || host.SNIs["name-0999.example"] != 2 || len(host.Devices) != 1 || len(host.Ja4Fingerprints) != 1 {
		t.Fatal("normalized properties lost counts or set semantics")
	}
	if h := store.Health(); h.PeakBytes > h.LimitBytes || h.Evictions == 0 {
		t.Fatal(h)
	}
}

func TestStoredDPISampleLimitsAvoidExtraPacketCopies(t *testing.T) {
	store, err := aggregate.Open(t.TempDir(), 2048, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	p := connectionBenchmarkPackets(t, 1)[0]
	key := streamKey{srcIP: "192.0.2.1", dstIP: "198.51.100.1", srcPort: "first", dstPort: "80", protocol: "TCP"}
	prefix := "samples/"
	if err = store.Do(func(tx *aggregate.Tx) error {
		for range maxPacketsPerStream {
			if err := bufferStoredDPI(tx, prefix, key, p); err != nil {
				return err
			}
		}
		// A nil packet is safe only if a saturated stream never reaches cloning.
		if err := bufferStoredDPI(tx, prefix, key, nil); err != nil {
			return err
		}
		for i := 0; i < maxStreamsPerProfile-1; i++ {
			key.srcPort = fmt.Sprint(i)
			if err := bufferStoredDPI(tx, prefix, key, p); err != nil {
				return err
			}
		}
		key.srcPort = "overflow"
		if err := bufferStoredDPI(tx, prefix, key, nil); err != nil {
			return err
		}
		streams, _, err := storedCounter(tx, prefix+"count")
		if err != nil {
			return err
		}
		packets, err := tx.Count(prefix + "packets/")
		if err != nil {
			return err
		}
		if streams != maxStreamsPerProfile || packets != maxStreamsPerProfile-1+maxPacketsPerStream {
			return fmt.Errorf("sample admission differs: streams=%d packets=%d", streams, packets)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
