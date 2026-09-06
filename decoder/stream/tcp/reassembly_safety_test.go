package tcp

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/stream/network"
	"github.com/dreadl0ck/netcap/decoder/stream/udp"
	"github.com/dreadl0ck/netcap/reassembly"
)

func TestReassemblePacketRejectsFragments(t *testing.T) {
	old := decoderconfig.Instance
	oldNetwork, oldUDP := network.Streams, udp.Streams
	defer func() {
		decoderconfig.Instance = old
		network.Streams, udp.Streams = oldNetwork, oldUDP
	}()
	decoderconfig.Instance.Quiet = true
	decoderconfig.Instance.SaveConns = true
	decoderconfig.Instance.NumStreamWorkers = 1
	decoderconfig.Instance.Out = t.TempDir()
	for _, defrag := range []bool{false, true} {
		decoderconfig.Instance.DefragIPv4 = defrag
		for _, protocol := range []layers.IPProtocol{layers.IPProtocolTCP, layers.IPProtocolUDP} {
			for _, version := range []int{4, 6} {
				for _, offset := range []uint16{0, 3} {
					network.ResetStreams()
					udp.ResetStreams()
					buf := gopacket.NewSerializeBuffer()
					var segment gopacket.SerializableLayer = &layers.TCP{SrcPort: 12345, DstPort: 80, SYN: true, Seq: 100}
					if protocol == layers.IPProtocolUDP {
						segment = &layers.UDP{SrcPort: 12345, DstPort: 53, BaseLayer: layers.BaseLayer{Payload: []byte("partial UDP payload")}}
					}
					var first gopacket.LayerType
					var wire []gopacket.SerializableLayer
					if version == 4 {
						first = layers.LayerTypeIPv4
						wire = []gopacket.SerializableLayer{&layers.IPv4{
							Version: 4, TTL: 64, Protocol: protocol,
							SrcIP: net.IPv4(10, 0, 0, 1), DstIP: net.IPv4(10, 0, 0, 2),
							Flags: layers.IPv4MoreFragments, FragOffset: offset,
						}, segment, gopacket.Payload("partial TCP payload")}
					} else {
						first = layers.LayerTypeIPv6
						// IPv6Fragment has no serializer; encode its eight-byte wire header.
						fragment := []byte{byte(protocol), 0, byte(offset >> 5), byte(offset<<3) | 1, 0, 0, 0, 1}
						wire = []gopacket.SerializableLayer{&layers.IPv6{
							Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolIPv6Fragment,
							SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2"),
						}, gopacket.Payload(fragment), segment, gopacket.Payload("partial TCP payload")}
					}
					if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, wire...); err != nil {
						t.Fatal(err)
					}
					packet := gopacket.NewPacket(buf.Bytes(), first, gopacket.Default)
					if packet.ErrorLayer() != nil {
						t.Fatal(packet.ErrorLayer().Error())
					}
					factory := newStreamFactory()
					assembler := reassembly.NewAssembler(reassembly.NewStreamPool(factory))
					ReassemblePacket(packet, assembler)
					// A custom packet decoder may expose TCP/UDP on a first fragment.
					// The IP fragment guard must still prevent partial assembly.
					packet.(gopacket.PacketBuilder).AddLayer(segment.(gopacket.Layer))
					ReassemblePacket(packet, assembler)
					if len(factory.streamReaders) != 0 {
						t.Fatalf("IPv%d offset %d defrag %v created TCP readers", version, offset, defrag)
					}
					before := network.NumSavedNetworkConns()
					network.FlushNetworkStreams()
					if network.NumSavedNetworkConns() != before+1 {
						t.Fatalf("IPv%d offset %d %v defrag %v lost network conversation", version, offset, protocol, defrag)
					}
					before = udp.NumSavedUDPConns()
					udp.FlushUDPStreams()
					if udp.NumSavedUDPConns() != before {
						t.Fatal("partial fragment reached UDP stream processing")
					}
				}
			}
		}
	}
}

func TestPrivatePoolCleanup(t *testing.T) {
	for _, wait := range []bool{false, true} {
		t.Run(map[bool]string{false: "force", true: "wait"}[wait], func(t *testing.T) {
			oldFactory, oldConfig := StreamFactory, decoderconfig.Instance
			StreamFactory = newStreamFactory()
			defer func() { StreamFactory, decoderconfig.Instance = oldFactory, oldConfig }()
			decoderconfig.Instance.Quiet = true
			decoderconfig.Instance.Debug = true
			decoderconfig.Instance.MemProfile = ""
			decoderconfig.Instance.SaveConns = false
			decoderconfig.Instance.WaitForConnections = wait
			decoderconfig.Instance.NumStreamWorkers = 0
			decoderconfig.Instance.Checksum = false
			decoderconfig.Instance.RemoveClosedStreams = true
			decoderconfig.Instance.AllowMissingInit = true
			decoderconfig.Instance.IgnoreFSMerr = true
			decoderconfig.Instance.StreamDecoderBufSize = 1
			decoderconfig.Instance.FlushEvery = 1

			const workers = 8
			assemblers := make([]*reassembly.Assembler, workers)
			var wg sync.WaitGroup
			for i := range assemblers {
				assemblers[i] = reassembly.NewAssembler(reassembly.NewStreamPool(StreamFactory))
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					buf := gopacket.NewSerializeBuffer()
					err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
						&layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP,
							SrcIP: net.IPv4(10, 0, 0, byte(i+1)), DstIP: net.IPv4(10, 0, 1, 1)},
						&layers.TCP{SrcPort: 12345, DstPort: 80, ACK: true, Seq: 100},
						gopacket.Payload("buffered until flush"))
					if err != nil {
						t.Error(err)
						return
					}
					packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
					packet.Metadata().Timestamp = time.Now()
					ReassemblePacket(packet, assemblers[i])
					if i%2 == 0 {
						assemblers[i].FlushAll()
					}
				}(i)
			}
			wg.Wait()
			if StreamFactory.StreamPool != nil {
				t.Fatal("private pools retained an unused singleton pool")
			}
			if len(StreamFactory.streamReaders) != workers*2 {
				t.Fatalf("readers = %d", len(StreamFactory.streamReaders))
			}
			saved := 0
			for _, s := range StreamFactory.streamReaders {
				if s.Saved() {
					saved++
					continue
				}
				if s.NumBytes() != 0 {
					t.Fatal("test payload was not buffered until cleanup")
				}
			}
			if saved != workers {
				t.Fatalf("saved readers = %d, want %d from worker maintenance only", saved, workers)
			}
			// An unpooled connection exercises fallback processing after reader EOF.
			StreamFactory.New(gopacket.NewFlow(layers.EndpointIPv4, []byte{10, 1, 0, 1}, []byte{10, 1, 0, 2}),
				gopacket.NewFlow(layers.EndpointTCPPort, []byte{1, 1}, []byte{0, 80}),
				&context{CaptureInfo: gopacket.CaptureInfo{Timestamp: time.Now()}})
			CleanupReassembly(wait, assemblers)
			// Both public close functions remain safe for post-join external callers.
			for range 4 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					CloseStreamReaderChannelsAndWait()
					CloseStreamReaderChannelsAndWaitQuiet()
				}()
			}
			wg.Wait()
			if StreamFactory.closedReaders != len(StreamFactory.streamReaders) {
				t.Fatalf("cleanup closed %d of %d reader channels",
					StreamFactory.closedReaders, len(StreamFactory.streamReaders))
			}
			if StreamFactory.numActive != 0 {
				t.Fatalf("cleanup returned with %d active readers", StreamFactory.numActive)
			}
			for _, s := range StreamFactory.streamReaders {
				if !s.Saved() {
					t.Fatal("cleanup failed to finalize a stream")
				}
			}
			for _, s := range StreamFactory.streamReaders[:workers*2] {
				if s.IsClient() && s.NumBytes() != len("buffered until flush") {
					t.Fatalf("cleanup lost buffered payload: got %d bytes", s.NumBytes())
				}
			}
			for _, a := range assemblers {
				if closed := a.FlushAll(); closed != 0 {
					t.Fatalf("cleanup left %d connections", closed)
				}
			}
		})
	}
}

// The capture binary and the web UI close reader channels again after cleanup
// has already reset the factory. That call must not consume the close for the
// readers a later capture registers, or their cleanup waits forever.
func TestCloseStreamReadersAfterFactoryReset(t *testing.T) {
	oldFactory, oldConfig := StreamFactory, decoderconfig.Instance
	defer func() { StreamFactory, decoderconfig.Instance = oldFactory, oldConfig }()
	decoderconfig.Instance.Quiet = true
	decoderconfig.Instance.SaveConns = false
	decoderconfig.Instance.StreamDecoderBufSize = 1

	ResetStreamFactory()
	// Post-cleanup call by an external caller, before the next capture starts.
	CloseStreamReaderChannelsAndWaitQuiet()

	StreamFactory.New(gopacket.NewFlow(layers.EndpointIPv4, []byte{10, 0, 0, 1}, []byte{10, 0, 0, 2}),
		gopacket.NewFlow(layers.EndpointTCPPort, []byte{48, 57}, []byte{0, 80}),
		&context{CaptureInfo: gopacket.CaptureInfo{Timestamp: time.Now()}})

	done := make(chan struct{})
	go func() {
		defer close(done)
		CloseStreamReaderChannelsAndWaitQuiet()
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("readers registered after a reset were never closed")
	}
}

func TestDefragUnsupportedWarning(t *testing.T) {
	oldConfig, oldLog := decoderconfig.Instance, reassemblyLog
	defer func() { decoderconfig.Instance, reassemblyLog = oldConfig, oldLog }()
	core, logs := observer.New(zap.WarnLevel)
	decoderconfig.Instance.DefragIPv4 = false
	SetLogger(zap.New(core))
	if logs.Len() != 0 {
		t.Fatal("warning emitted with defragmentation disabled")
	}
	decoderconfig.Instance.DefragIPv4 = true
	SetLogger(zap.New(core))
	if logs.FilterMessageSnippet("DefragIPv4 is unsupported").Len() != 1 {
		t.Fatal("missing initialization warning for unsupported defragmentation")
	}
}

// Compare the lazy-packet decoding cost before and after the fragment guard.
func BenchmarkTCPFragmentInspection(b *testing.B) {
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
		&layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP,
			SrcIP: net.IPv4(10, 0, 0, 1), DstIP: net.IPv4(10, 0, 0, 2)},
		&layers.TCP{SrcPort: 12345, DstPort: 80, SYN: true},
		gopacket.Payload(make([]byte, 1400))); err != nil {
		b.Fatal(err)
	}
	for _, full := range []bool{true, false} {
		b.Run(map[bool]string{true: "all-layers", false: "network-first"}[full], func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
				if full {
					for _, layer := range packet.Layers() {
						if ip, ok := layer.(*layers.IPv4); ok && (ip.FragOffset != 0 || ip.Flags&layers.IPv4MoreFragments != 0) {
							b.Fatal("unexpected fragment")
						}
					}
				} else {
					ip := packet.NetworkLayer().(*layers.IPv4)
					if ip.FragOffset != 0 || ip.Flags&layers.IPv4MoreFragments != 0 {
						b.Fatal("unexpected fragment")
					}
				}
				if packet.Layer(layers.LayerTypeTCP) == nil {
					b.Fatal("missing TCP")
				}
			}
		})
	}
}
