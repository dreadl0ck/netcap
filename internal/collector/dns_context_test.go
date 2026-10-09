package collector

import (
	"fmt"
	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/packet"
	"github.com/dreadl0ck/netcap/internal/filter"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func contextCaptureFixture(t *testing.T) string {
	t.Helper()
	in, err := os.Open(filepath.Join("..", "networkdetect", "testdata", "live", "c2.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	reader, err := pcapgo.NewReader(in)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "context.pcap")
	out, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	writer := pcapgo.NewWriterNanos(out)
	if err := writer.WriteFileHeader(65535, reader.LinkType()); err != nil {
		t.Fatal(err)
	}
	for {
		data, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		if layer := p.Layer(layers.LayerTypeDNS); layer != nil {
			dns := layer.(*layers.DNS)
			// The retained replay has TTL=0; this derivative tests valid caching.
			for i := range dns.Answers {
				dns.Answers[i].TTL = 60
			}
			udp := p.TransportLayer().(*layers.UDP)
			ipv4 := p.NetworkLayer().(*layers.IPv4)
			if err := udp.SetNetworkLayerForChecksum(ipv4); err != nil {
				t.Fatal(err)
			}
			buffer := gopacket.NewSerializeBuffer()
			if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, p.LinkLayer().(*layers.Ethernet), ipv4, udp, dns); err != nil {
				t.Fatal(err)
			}
			data = buffer.Bytes()
			ci.Length, ci.CaptureLength = len(data), len(data)
		}
		if err := writer.WritePacket(ci, data); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestCaptureDNSContextIsImmutableAcrossWorkerCountsAndOptional(t *testing.T) {
	input := contextCaptureFixture(t)
	var reference []string
	for _, enabled := range []bool{true, false} {
		for _, workers := range []int{1, 2, 4, 8} {
			t.Run(fmt.Sprintf("enabled=%v/workers=%d", enabled, workers), func(t *testing.T) {
				packet.ResetConnections()
				out := t.TempDir()
				dc := config.DefaultConfig.Clone()
				dc.Out, dc.Source, dc.IncludeDecoders, dc.Quiet = out, input, "Ethernet,IPv4,TCP,UDP,DNS,Connection", true
				c := New(Config{DNSResolutionContext: enabled, Workers: workers, PacketBufferSize: 100, BaseLayer: layers.LayerTypeEthernet, DecodeOptions: gopacket.Default, DecoderConfig: dc, ResolverConfig: resolvers.Config{}, NoPrompt: true, NoSignalHandling: true, OutDirPermission: 0700})
				if err := c.CollectPcap(input); err != nil {
					t.Fatal(err)
				}
				reader, err := netio.Open(filepath.Join(out, "Connection.ncap.gz"), 4096)
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Close()
				if _, err := reader.ReadHeader(); err != nil {
					t.Fatal(err)
				}
				var got []string
				resolved := 0
				for {
					var record types.Connection
					if err := reader.Next(&record); err == io.EOF {
						break
					} else if err != nil {
						t.Fatal(err)
					}
					if !enabled && (record.DNSResolutionState != "" || record.DNSResolvedName != "" || record.DNSResolvedAt != 0) {
						t.Fatalf("disabled feature emitted context: %s %s %d", record.DNSResolutionState, record.DNSResolvedName, record.DNSResolvedAt)
					}
					if record.DNSResolutionState == "resolved" {
						if record.DNSResolvedName == "api.open.wisdom.alphasoc.net" {
							resolved++
						}
						if !filter.DNSResolutionMatches(record.DNSResolutionState, record.DNSResolvedName, record.DNSResolvedAt, record.TimestampFirst, record.DNSResolvedName, 60e9) {
							t.Fatalf("capture-time rule rejected retained context: %+v", record)
						}
					}
					got = append(got, fmt.Sprintf("%s|%d|%s|%s|%d", record.CommunityID, record.TimestampFirst, record.DNSResolutionState, record.DNSResolvedName, record.DNSResolvedAt))
				}
				if enabled {
					if resolved == 0 {
						t.Fatal("no capture-time DNS context")
					}
					sort.Strings(got)
					if workers == 1 {
						reference = got
					} else if !reflect.DeepEqual(got, reference) {
						t.Fatal("worker count changed capture-time context")
					}
				}
			})
		}
	}
}
