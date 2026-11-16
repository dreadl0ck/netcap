package network

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/aggregate"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/dreadl0ck/netcap/internal/packetview/testutil"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func networkStorageSetup(t *testing.T, limit int64) *aggregate.Store {
	t.Helper()
	oldConfig, oldPool := decoderconfig.Instance, Streams
	decoderconfig.Instance = &decoderconfig.Config{Out: t.TempDir(), Quiet: true, SaveConns: true, NumStreamWorkers: 1, StreamBufferSize: 1}
	Streams = newNetworkStreamPool()
	var state *aggregate.Store
	if limit > 0 {
		var err error
		state, err = aggregate.Open(t.TempDir(), limit, nil)
		if err != nil {
			t.Fatal(err)
		}
		decoderconfig.Instance.AggregateStore = state
	}
	t.Cleanup(func() {
		if state != nil {
			_ = state.Close()
		}
		decoderconfig.Instance, Streams = oldConfig, oldPool
	})
	return state
}

func networkStoragePacket(payload []byte, reverse bool, at time.Time, ordinal uint64) gopacket.Packet {
	wire := testutil.Ethernet(testutil.IP(false, reverse, layers.IPProtocolICMPv4, testutil.Serialize(&layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(8, 0)}, gopacket.Payload(payload))))
	p := gopacket.NewPacket(wire, layers.LayerTypeEthernet, gopacket.Default)
	p.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: at, CaptureLength: len(wire), Length: len(wire), InterfaceIndex: 3, AncillaryData: []any{&packetview.Context{Scope: "if:3/vlan:7", Status: "wire", Packets: []*types.CapturePacketRef{{Ordinal: ordinal}}}}}
	return p
}

func TestNetworkRetentionDisabledWithoutConversationOutput(t *testing.T) {
	state := networkStorageSetup(t, 1024)
	decoderconfig.Instance.SaveConns = false
	p := networkStoragePacket([]byte("fixture"), false, time.Unix(1, 0), 1)
	for range 4096 {
		Streams.HandleNetworkPacket(p, []byte("fixture"), "ICMPv4")
	}
	if Streams.size() != 0 || state.Health().ResidentBytes != 0 || state.Health().DiskWrites != 0 {
		t.Fatal("disabled network output retained payloads", state.Health())
	}
}

func TestStoredNetworkOrderMetadataDirectionAndRestart(t *testing.T) {
	state := networkStorageSetup(t, 1024)
	start := time.Unix(1700000000, 0)
	for _, i := range []int{3, 1, 2} {
		payload := []byte(fmt.Sprint(i))
		p := networkStoragePacket(payload, i == 2, start.Add(time.Duration(i/2)*time.Second), uint64(i))
		Streams.HandleNetworkPacket(p, payload, "ICMPv4")
	}
	packet := networkStoragePacket(nil, false, start, 1)
	key := packet.NetworkLayer().NetworkFlow().FastHash() ^ packetview.ScopeHash(packet)
	source := &networkFragmentSource{state: state, prefix: networkDataPrefix(key), client: packet.NetworkLayer().NetworkFlow()}
	for range 2 {
		var values []string
		if err := source.Walk(func(f streamutils.NetworkDataFragment) bool {
			values = append(values, string(f.Raw()))
			ci := f.CaptureInfo()
			context := packetview.FromCapture(ci)
			if ci.InterfaceIndex != 3 || context == nil || context.Scope != "if:3/vlan:7" || len(context.Packets) != 1 || context.Packets[0].Ordinal != uint64(len(values)) {
				t.Fatal("network capture provenance lost", ci)
			}
			server := f.Direction() == reassembly.TCPDirServerToClient
			if server != (string(f.Raw()) == "2") {
				t.Fatal("network direction changed", f.Direction(), string(f.Raw()))
			}
			return true
		}); err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(values) != "[1 2 3]" {
			t.Fatal("network source order/restart changed", values)
		}
	}
	if Streams.size() != 0 {
		t.Fatal("stored network data also accumulated in memory")
	}
}

func TestStoredNetworkPreservesLegacyConversationBytes(t *testing.T) {
	var expected []byte
	for _, limit := range []int64{0, 1, 2048} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			networkStorageSetup(t, limit)
			for _, i := range []int{3, 1, 2} {
				payload := []byte(fmt.Sprint(i))
				p := networkStoragePacket(payload, i == 2, time.Unix(1700000000, int64(i/2)), uint64(i))
				Streams.HandleNetworkPacket(p, payload, "ICMPv4")
			}
			before := NumSavedNetworkConns()
			FlushNetworkStreams()
			if NumSavedNetworkConns() != before+1 {
				t.Fatal("network conversation not saved")
			}
			files, err := filepath.Glob(filepath.Join(decoderconfig.Instance.Out, "network", "icmpv4", "*.bin"))
			if err != nil || len(files) != 1 {
				t.Fatal(files, err)
			}
			got, err := os.ReadFile(files[0])
			if err != nil {
				t.Fatal(err)
			}
			if limit == 0 {
				expected = got
			}
			if string(got) != "123" || !bytes.Equal(got, expected) {
				t.Fatal("network payload bytes changed", string(got), string(expected))
			}
		})
	}
}

func TestStoredNetworkDoesNotRetainConversationPayload(t *testing.T) {
	state := networkStorageSetup(t, 65536)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	payload := bytes.Repeat([]byte{0xa5}, 1024)
	for i := range 32768 {
		p := networkStoragePacket(payload, i%2 == 1, time.Unix(1700000000, int64(i)), uint64(i+1))
		Streams.HandleNetworkPacket(p, p.Layer(layers.LayerTypeICMPv4).LayerPayload(), "ICMPv4")
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	retained := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	health := state.Health()
	t.Logf("network payload=33554432 retainedGoHeap=%d cachePeak=%d database=%d", retained, health.PeakBytes, health.DatabaseBytes)
	if retained > 8<<20 || health.PeakBytes > 65536 || health.DiskWrites == 0 || Streams.size() != 0 {
		t.Fatal("network source retained a complete conversation", retained, health)
	}
}

func TestStoredNetworkOutputFailureReachesBackingStore(t *testing.T) {
	state := networkStorageSetup(t, 1024)
	if err := os.WriteFile(filepath.Join(decoderconfig.Instance.Out, "network"), []byte("block directory"), 0600); err != nil {
		t.Fatal(err)
	}
	p := networkStoragePacket([]byte("fixture"), false, time.Unix(1, 0), 1)
	Streams.HandleNetworkPacket(p, []byte("fixture"), "ICMPv4")
	before := NumSavedNetworkConns()
	FlushNetworkStreams()
	if state.Error() == nil || NumSavedNetworkConns() != before {
		t.Fatal("failed network output was silently accepted", state.Error())
	}
}
