package collector

import (
	"encoding/binary"
	"runtime"
	"testing"

	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestPKTAPLinkTypes(t *testing.T) {
	for _, lt := range []layers.LinkType{258, 149} {
		want := lt == 258 || runtime.GOOS == "darwin"
		if (linkTypeToLayerType(lt) == layers.LayerTypePktap) != want {
			t.Fatalf("link mapping %d", lt)
		}
		c := rawPacketCollector(1, 1, gopacket.Default)
		c.config.DecoderConfig = &config.Config{Quiet: true}
		err := c.handleLinkType(lt)
		if (err == nil) != want || (want && c.config.BaseLayer != layers.LayerTypePktap) {
			t.Fatalf("capture mapping %d: %v", lt, err)
		}
	}
}

func TestPKTAPMixedLinks(t *testing.T) {
	inner := rawPacketFixture(t, false, 64)
	wrapped := make([]byte, 156)
	binary.LittleEndian.PutUint32(wrapped, 156)
	binary.LittleEndian.PutUint32(wrapped[4:], 1)
	binary.LittleEndian.PutUint32(wrapped[8:], 1)
	wrapped = append(wrapped, inner...)
	c := rawPacketCollector(1, 1, gopacket.Default)
	c.config.BaseLayer = layers.LayerTypePktap
	for _, tt := range []struct {
		lt    layers.LinkType
		data  []byte
		pktap bool
	}{
		{258, wrapped, true}, {layers.LinkTypeEthernet, inner, false}, {258, wrapped, true},
		{layers.LinkTypeIPv4, inner[14:], false}, {149, wrapped, runtime.GOOS == "darwin"},
	} {
		ci := gopacket.CaptureInfo{AncillaryData: []any{tt.lt}, CaptureLength: len(tt.data), Length: len(tt.data)}
		c.handleRawPacketData(tt.data, &ci)
		p := <-c.workers[0]
		if (p.Layer(layers.LayerTypePktap) != nil) != tt.pktap || p.ErrorLayer() != nil {
			t.Fatalf("mixed link %d: %v", tt.lt, p)
		}
		if tt.lt != 149 && p.Layer(layers.LayerTypeUDP) == nil {
			t.Fatal("inner UDP lost")
		}
		if c.config.BaseLayer != layers.LayerTypePktap {
			t.Fatal("per-packet mapping changed base")
		}
	}
}
