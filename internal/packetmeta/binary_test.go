package packetmeta

import (
	"reflect"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/linkaudit"
	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
)

func TestCaptureMetadataRoundTrip(t *testing.T) {
	for _, timestamp := range []time.Time{{}, time.Unix(-1, 123).UTC(), time.Unix(1700000000, 999999999).UTC()} {
		ci := gopacket.CaptureInfo{Timestamp: timestamp, CaptureLength: 62, Length: 66, InterfaceIndex: 7, AncillaryData: []any{packetview.CaptureInterface(42), packetview.TimestampMissing(true), &linkaudit.FrameCheck{Known: true, Present: true}, &packetview.Context{Scope: "if:7/vlan:3/\xff", Status: "reassembled", Reassembled: true, SyntheticNetwork: true, CompletedAt: time.Unix(1700000001, 1).UTC(), Packets: []*types.CapturePacketRef{{Ordinal: 19, TimestampUnavailable: true}}, Tunnels: []*types.Encapsulation{{}}}}}
		wire, err := Marshal(ci)
		if err != nil {
			t.Fatal(err)
		}
		restored, err := Unmarshal(wire)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(Save(ci), Save(restored)) {
			t.Fatalf("capture metadata changed: %+v %+v", Save(ci), Save(restored))
		}
		for i := 0; i < len(wire); i++ {
			if _, err := Unmarshal(wire[:i]); err == nil {
				t.Fatalf("truncated metadata accepted at %d", i)
			}
		}
		if _, err = Unmarshal(append(wire, 0)); err == nil {
			t.Fatal("trailing metadata accepted")
		}
	}
}

func FuzzStoredCaptureMetadata(f *testing.F) {
	wire, _ := Marshal(gopacket.CaptureInfo{Timestamp: time.Unix(1, 2), CaptureLength: 42, Length: 42})
	f.Add(wire)
	f.Add([]byte{1, 8, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			return
		}
		_, _ = Unmarshal(data)
	})
}
