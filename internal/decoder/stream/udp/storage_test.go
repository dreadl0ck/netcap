package udp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/aggregate"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/dreadl0ck/netcap/internal/packetview/testutil"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func storedUDPPacket(payload []byte, at time.Time, ordinal uint64) gopacket.Packet {
	wire := make([]byte, 28+len(payload))
	wire[0], wire[8], wire[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(wire[2:], uint16(len(wire)))
	copy(wire[12:], []byte{192, 0, 2, 1})
	copy(wire[16:], []byte{198, 51, 100, 1})
	binary.BigEndian.PutUint16(wire[20:], 40000)
	binary.BigEndian.PutUint16(wire[22:], 9999)
	binary.BigEndian.PutUint16(wire[24:], uint16(8+len(payload)))
	copy(wire[28:], payload)
	p := gopacket.NewPacket(testutil.Ethernet(wire), layers.LayerTypeEthernet, gopacket.Default)
	p.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: at, CaptureLength: len(p.Data()), Length: len(p.Data()), InterfaceIndex: 3, AncillaryData: []any{&packetview.Context{Scope: "if:3/vlan:7", Status: "wire", Packets: []*types.CapturePacketRef{{Ordinal: ordinal}}}}}
	return p
}

func storedUDPSetup(t *testing.T, limit int64) *aggregate.Store {
	t.Helper()
	old := decoderconfig.Instance
	cfg := old.Clone()
	decoderconfig.Instance = cfg
	state, err := aggregate.Open(t.TempDir(), limit, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AggregateStore = state
	t.Cleanup(func() { _ = state.Close(); decoderconfig.Instance = old })
	return state
}

func TestStoredUDPOrderMetadataAndRestart(t *testing.T) {
	state := storedUDPSetup(t, 2048)
	pool := newUDPStreamPool()
	start := time.Unix(1700000000, 0)
	for _, i := range []int{3, 1, 2} {
		p := storedUDPPacket([]byte(fmt.Sprint(i)), start.Add(time.Duration(i/2)*time.Second), uint64(i))
		pool.HandleUDP(p, p.TransportLayer())
	}
	p := storedUDPPacket(nil, start, 1)
	key := udpConversationKey(p)
	source := &udpFragmentSource{state: state, prefix: udpDataPrefix(key), count: 3}
	for range 2 {
		var values []string
		if err := source.Walk(func(f core.DataFragment) bool {
			values = append(values, string(f.Raw()))
			if packetview.Scope(&fragmentPacket{Packet: p, info: f.CaptureInfo()}) != "if:3/vlan:7" {
				t.Fatal("scope lost")
			}
			return true
		}); err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(values) != "[1 2 3]" {
			t.Fatal(values)
		}
	}
	if len(pool.streams) != 0 {
		t.Fatal("stored datagrams also retained in memory")
	}
}

type fragmentPacket struct {
	gopacket.Packet
	info gopacket.CaptureInfo
}

func (p *fragmentPacket) Metadata() *gopacket.PacketMetadata {
	return &gopacket.PacketMetadata{CaptureInfo: p.info}
}

func TestStoredUDPDoesNotRetainConversationPayload(t *testing.T) {
	state := storedUDPSetup(t, 65536)
	pool := newUDPStreamPool()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	payload := bytes.Repeat([]byte{0xa5}, 1024)
	const count = 32768
	for i := 0; i < count; i++ {
		p := storedUDPPacket(payload, time.Unix(1700000000, int64(i)), uint64(i+1))
		pool.HandleUDP(p, p.TransportLayer())
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	retained := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	if retained > 8<<20 {
		t.Fatalf("retained %d bytes for a 32 MiB UDP conversation", retained)
	}
	p := storedUDPPacket(nil, time.Unix(0, 0), 1)
	source := &udpFragmentSource{state: state, prefix: udpDataPrefix(udpConversationKey(p)), count: count, frozen: true}
	n := 0
	if err := source.Walk(func(f core.DataFragment) bool {
		if !bytes.Equal(f.Raw(), payload) {
			t.Fatal("spilled payload changed")
		}
		n++
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if n != count || len(pool.streams) != 0 {
		t.Fatal("datagrams lost or retained", n, len(pool.streams))
	}
	if source.cacheReady || len(source.cached) != 0 {
		t.Fatal("large frozen conversation was cached whole")
	}
	t.Logf("retained Go heap for 32 MiB UDP payload: %d bytes; cache health: %+v", retained, state.Health())
}

func TestFrozenUDPWorkingSetIsRestartableAndDetached(t *testing.T) {
	state := storedUDPSetup(t, 1024)
	pool := newUDPStreamPool()
	for i := 1; i <= 3; i++ {
		p := storedUDPPacket([]byte(fmt.Sprint(i)), time.Unix(100, int64(i)), uint64(i))
		pool.HandleUDP(p, p.TransportLayer())
	}
	p := storedUDPPacket(nil, time.Unix(100, 0), 1)
	source := &udpFragmentSource{state: state, prefix: udpDataPrefix(udpConversationKey(p)), count: 3, frozen: true}
	if err := source.Walk(func(f core.DataFragment) bool {
		f.Raw()[0] = 'x'
		if err := state.Do(func(tx *aggregate.Tx) error { _, _, err := tx.Get("unrelated"); return err }); err != nil {
			t.Fatal(err)
		}
		return false
	}); err != nil {
		t.Fatal(err)
	}
	reads := state.Health().DiskReads
	var values []string
	if err := source.Walk(func(f core.DataFragment) bool { values = append(values, string(f.Raw())); return true }); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(values) != "[1 2 3]" || state.Health().DiskReads != reads {
		t.Fatal("working-set cache changed data or reread storage", values)
	}
}
