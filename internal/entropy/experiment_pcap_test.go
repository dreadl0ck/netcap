//go:build entropyexperiment && (darwin || linux)

package entropy

import (
	"io"
	"os"
	"syscall"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// BenchmarkCapturePayloads replays the entropy inputs of four packet decoders.
// Set NETCAP_ENTROPY_PCAP to an Ethernet pcapng. Reading/decoding is not timed.
func BenchmarkCapturePayloads(b *testing.B) {
	path := os.Getenv("NETCAP_ENTROPY_PCAP")
	if path == "" {
		b.Skip("set NETCAP_ENTROPY_PCAP to an Ethernet pcapng")
	}
	f, err := os.Open(path)
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		b.Fatal(err)
	}
	if r.LinkType() != layers.LinkTypeEthernet {
		b.Fatal("expected Ethernet pcapng")
	}
	var payloads [][]byte
	var total int64
	var large, packets int
	for {
		data, _, err := r.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			b.Fatal(err)
		}
		packets++
		packet := gopacket.NewPacket(data, r.LinkType(), gopacket.Default)
		for _, layer := range packet.Layers() {
			switch layer.LayerType() {
			case layers.LayerTypeEthernet, layers.LayerTypeIPv4, layers.LayerTypeTCP, layers.LayerTypeUDP:
				payload := layer.LayerPayload()
				payloads = append(payloads, payload)
				total += int64(len(payload))
				if len(payload) >= 16384 {
					large++
				}
			}
		}
	}
	if len(payloads) == 0 {
		b.Fatal("capture has no matching packet layers")
	}
	b.Logf("%d packets, %d entropy inputs, %d bytes, %d inputs >= 16 KiB", packets, len(payloads), total, large)
	for _, impl := range []struct {
		name string
		fn   func([]byte) float64
	}{{"Bytes", Bytes}, {"Go4", BytesGo4}, {experimentASMName, BytesARM64}} {
		b.Run(impl.name, func(b *testing.B) {
			b.SetBytes(total)
			b.ReportAllocs()
			var before, after syscall.Rusage
			if err := syscall.Getrusage(syscall.RUSAGE_SELF, &before); err != nil {
				b.Fatal(err)
			}
			for b.Loop() {
				var sum float64
				for _, payload := range payloads {
					sum += impl.fn(payload)
				}
				entropySink = sum
			}
			if err := syscall.Getrusage(syscall.RUSAGE_SELF, &after); err != nil {
				b.Fatal(err)
			}
			cpu := after.Utime.Nano() + after.Stime.Nano() - before.Utime.Nano() - before.Stime.Nano()
			b.ReportMetric(float64(cpu)/float64(b.N), "cpu-ns/op")
			b.ReportMetric(float64(large), "large-inputs/op")
			b.ReportMetric(float64(len(payloads)), "inputs/op")
		})
	}
}
