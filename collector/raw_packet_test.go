package collector

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func rawPacketFixture(tb testing.TB, tcp bool, size int) []byte {
	tb.Helper()
	eth := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.IPv4(10, 0, 0, 1), DstIP: net.IPv4(10, 0, 0, 2)}
	var transport gopacket.SerializableLayer
	headerSize := 42
	if tcp {
		ip.Protocol = layers.IPProtocolTCP
		layer := &layers.TCP{SrcPort: 40000, DstPort: 40001, ACK: true, Seq: 1, Window: 4096}
		if err := layer.SetNetworkLayerForChecksum(ip); err != nil {
			tb.Fatal(err)
		}
		transport, headerSize = layer, 54
	} else {
		ip.Protocol = layers.IPProtocolUDP
		layer := &layers.UDP{SrcPort: 40000, DstPort: 40001}
		if err := layer.SetNetworkLayerForChecksum(ip); err != nil {
			tb.Fatal(err)
		}
		transport = layer
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, ip, transport, gopacket.Payload(bytes.Repeat([]byte{0xa5}, size-headerSize))); err != nil {
		tb.Fatal(err)
	}
	return buf.Bytes()
}

func rawPacketCollector(workers, capacity int, options gopacket.DecodeOptions) *Collector {
	c := &Collector{
		config:     &Config{BaseLayer: layers.LayerTypeEthernet, DecodeOptions: options},
		numWorkers: workers, workers: make([]chan gopacket.Packet, workers),
	}
	for i := range c.workers {
		c.workers[i] = make(chan gopacket.Packet, capacity)
	}
	return c
}

func releaseRawPacket(p gopacket.Packet) {
	if pooled, ok := p.(gopacket.PooledPacket); ok {
		pooled.Dispose()
	}
}

func checkRawPacket(t *testing.T, got gopacket.Packet, data []byte, base gopacket.LayerType, ci gopacket.CaptureInfo) {
	t.Helper()
	want := gopacket.NewPacket(data, base, gopacket.Default)
	want.Metadata().CaptureInfo = ci
	if !bytes.Equal(got.Data(), want.Data()) || !reflect.DeepEqual(got.Layers(), want.Layers()) {
		t.Errorf("packet content differs: got %v, want %v", got, want)
	}
	if !reflect.DeepEqual(got.Metadata(), want.Metadata()) {
		t.Errorf("metadata = %+v, want %+v", got.Metadata(), want.Metadata())
	}
	if (got.ErrorLayer() != nil) != (want.ErrorLayer() != nil) {
		t.Errorf("decode error = %v, want %v", got.ErrorLayer(), want.ErrorLayer())
	}
}

func TestHandleRawPacketDataContent(t *testing.T) {
	udp := rawPacketFixture(t, false, 64)
	tcp := rawPacketFixture(t, true, 512)
	for _, tc := range []struct {
		name      string
		data      []byte
		base      gopacket.LayerType
		ancillary []any
		strip     int
		truncated bool
		decodeErr bool
	}{
		{name: "UDP", data: udp, base: layers.LayerTypeEthernet},
		{name: "TCP", data: tcp, base: layers.LayerTypeEthernet},
		{name: "truncated", data: tcp[:40], base: layers.LayerTypeEthernet, truncated: true, decodeErr: true},
		{name: "malformed", data: []byte{1, 2, 3}, base: layers.LayerTypeEthernet, decodeErr: true},
		{name: "ancillary_raw_IPv4", data: udp[14:], base: layers.LayerTypeIPv4, ancillary: []any{layers.LinkTypeRaw}},
		{name: "FPP_override", data: append(bytes.Repeat([]byte{0x55}, 8), udp...), base: layers.LayerTypeEthernet, ancillary: []any{layers.LinkType(274)}, strip: 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := rawPacketCollector(1, 1, gopacket.Default)
			if tc.strip != 0 {
				c.config.BaseLayer = layers.LayerTypeIPv4
			}
			ci := gopacket.CaptureInfo{Timestamp: time.Unix(123, 456), CaptureLength: len(tc.data), Length: len(tc.data) + 10, InterfaceIndex: 7, AncillaryData: tc.ancillary}
			c.handleRawPacketData(tc.data, &ci)
			p := <-c.workers[0]
			defer releaseRawPacket(p)
			checkRawPacket(t, p, tc.data[tc.strip:], tc.base, ci)
			if p.Metadata().Truncated != tc.truncated || (p.ErrorLayer() != nil) != tc.decodeErr {
				t.Errorf("truncated/error = %v/%v, want %v/%v", p.Metadata().Truncated, p.ErrorLayer(), tc.truncated, tc.decodeErr)
			}
		})
	}
}

func TestHandleRawPacketDataOptions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options gopacket.DecodeOptions
		alias   bool
	}{
		{"default", gopacket.DecodeOptions{}, true},
		{"lazy", gopacket.Lazy, false},
		{"nocopy", gopacket.NoCopy, true},
		{"pool", gopacket.DecodeOptions{Pool: true}, false},
		{"datagrams", gopacket.DecodeStreamsAsDatagrams, false},
		{"custom_recovery", gopacket.DecodeOptions{SkipDecodeRecovery: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := rawPacketFixture(t, true, 64)
			c := rawPacketCollector(1, 1, tc.options)
			ci := gopacket.CaptureInfo{CaptureLength: len(data), Length: len(data)}
			c.handleRawPacketData(data, &ci)
			p := <-c.workers[0]
			defer releaseRawPacket(p)
			if c.config.DecodeOptions != tc.options {
				t.Errorf("configured options mutated: %+v", c.config.DecodeOptions)
			}
			if alias := &p.Data()[0] == &data[0]; alias != tc.alias {
				t.Errorf("input alias = %v, want %v", alias, tc.alias)
			}
			if _, pooled := p.(gopacket.PooledPacket); pooled != tc.options.Pool {
				t.Errorf("pooled = %v, want %v", pooled, tc.options.Pool)
			}
			// PooledPacket wraps Packet and does not expose DecodeOptions.
			if decoded, ok := p.(interface {
				DecodeOptions() *gopacket.DecodeOptions
			}); ok {
				want := tc.options
				if want == (gopacket.DecodeOptions{}) {
					want.NoCopy = true
				}
				if *decoded.DecodeOptions() != want {
					t.Errorf("packet options = %+v, want %+v", *decoded.DecodeOptions(), want)
				}
			} else if !tc.options.Pool {
				t.Fatal("packet does not expose decode options")
			}
			checkRawPacket(t, p, data, layers.LayerTypeEthernet, ci)
		})
	}
}

func TestHandleRawPacketDataDelayedQueue(t *testing.T) {
	var capture bytes.Buffer
	w := pcapgo.NewWriter(&capture)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	want := make([][]byte, 6)
	for i := range want {
		want[i] = rawPacketFixture(t, i%2 == 0, 64+i*100)
		want[i][len(want[i])-1] = byte(i)
		ci := gopacket.CaptureInfo{Timestamp: time.Unix(int64(i+1), 0), CaptureLength: len(want[i]), Length: len(want[i])}
		if err := w.WritePacket(ci, want[i]); err != nil {
			t.Fatal(err)
		}
	}
	r, err := pcapgo.NewReader(&capture)
	if err != nil {
		t.Fatal(err)
	}
	c := rawPacketCollector(1, 3, gopacket.Default)
	infos := make([]gopacket.CaptureInfo, 3)
	for i := range infos {
		data, ci, err := r.ReadPacketData()
		if err != nil {
			t.Fatal(err)
		}
		infos[i] = ci
		c.handleRawPacketData(data, &ci)
	}
	packets := make([]gopacket.Packet, 3)
	for i := range packets {
		packets[i] = <-c.workers[0]
		defer releaseRawPacket(packets[i])
		checkRawPacket(t, packets[i], want[i], layers.LayerTypeEthernet, infos[i])
	}
	// Further allocating reads must not overwrite queued packets or decoded payloads.
	for range 3 {
		if _, _, err := r.ReadPacketData(); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := r.ReadPacketData(); err != io.EOF {
		t.Fatalf("end of capture = %v, want EOF", err)
	}
	for i, p := range packets {
		checkRawPacket(t, p, want[i], layers.LayerTypeEthernet, infos[i])
	}
}

func BenchmarkHandleRawPacketData(b *testing.B) {
	for _, protocol := range []string{"TCP", "UDP"} {
		for _, size := range []int{64, 512, 1514} {
			for _, workers := range []int{1, 4} {
				b.Run(fmt.Sprintf("%s/%d/workers%d", protocol, size, workers), func(b *testing.B) {
					data := rawPacketFixture(b, protocol == "TCP", size)
					ci := gopacket.CaptureInfo{CaptureLength: len(data), Length: len(data)}
					c := rawPacketCollector(workers, 1, gopacket.Default)
					probe := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
					idx := c.getSymmetricWorkerIndex(probe)
					releaseRawPacket(probe)
					b.SetBytes(int64(len(data)))
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						c.handleRawPacketData(data, &ci)
						releaseRawPacket(<-c.workers[idx])
					}
				})
			}
		}
	}
}
