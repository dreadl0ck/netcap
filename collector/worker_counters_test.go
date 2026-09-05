package collector

import (
	"reflect"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/decoder/config"
)

type counterTestLayer struct {
	layers.BaseLayer
	kind gopacket.LayerType
}

func (l counterTestLayer) LayerType() gopacket.LayerType { return l.kind }

func TestWorkerProtocolCounterSnapshots(t *testing.T) {
	const workers, packets = 4, 20
	for _, tt := range []struct {
		name    string
		kind    gopacket.LayerType
		unknown bool
	}{
		{"excluded decoder", layers.LayerTypeEthernet, true},
		{"payload", gopacket.LayerTypePayload, true},
		{"zero", gopacket.LayerTypeZero, true},
		{"decode failure", gopacket.LayerTypeDecodeFailure, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := New(Config{DecoderConfig: &config.Config{}})
			inputs := make([]chan gopacket.Packet, workers)
			for i := range inputs {
				inputs[i] = c.worker(nil)
				defer close(inputs[i])
			}
			decode := gopacket.DecodeFunc(func(_ []byte, builder gopacket.PacketBuilder) error {
				builder.AddLayer(&counterTestLayer{kind: tt.kind})
				return nil
			})
			for n := range packets {
				for _, in := range inputs {
					c.wg.Add(1)
					in <- gopacket.NewPacket(nil, decode, gopacket.Default)
				}
				// Workers remain live: snapshots require no shutdown or final merge.
				c.wg.Wait()
				want := map[string]int64{tt.kind.String(): int64((n + 1) * workers)}
				if got := c.allProtosAtomic.Snapshot(); !reflect.DeepEqual(got, want) {
					t.Fatalf("all protocols = %v, want %v", got, want)
				}
				total := int64((n + 1) * workers)
				if tt.kind == gopacket.LayerTypePayload {
					total = 0
				}
				if got := c.GetTotalAuditRecords(); got != total {
					t.Fatalf("total = %d, want %d", got, total)
				}
				if !tt.unknown {
					want = map[string]int64{}
				}
				if got := c.unknownProtosAtomic.Snapshot(); !reflect.DeepEqual(got, want) {
					t.Fatalf("unknown protocols = %v, want %v", got, want)
				}
			}
		})
	}
}
