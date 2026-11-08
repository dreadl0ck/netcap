package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/internal/networkdetect"
	"github.com/dreadl0ck/netcap/internal/packetview/testutil"
	"github.com/dreadl0ck/netcap/types"
)

func TestFragmentDetectionProcess(t *testing.T) {
	input := os.Getenv("NETCAP_FRAGMENT_DETECTION_INPUT")
	if input == "" {
		return
	}
	workers, _ := strconv.Atoi(os.Getenv("NETCAP_FRAGMENT_DETECTION_WORKERS"))
	c := New(Config{Workers: workers, PacketBufferSize: 8, NoSignalHandling: true, NoPrompt: true,
		BaseLayer: layers.LayerTypeEthernet, DecodeOptions: gopacket.Default, NetworkDetection: true,
		NetworkDetectionConfig: os.Getenv("NETCAP_FRAGMENT_DETECTION_CONFIG"),
		DecoderConfig: &config.Config{Out: os.Getenv("NETCAP_FRAGMENT_DETECTION_OUT"), Quiet: true,
			IncludeDecoders: "IPv4,IPv6,TCP,UDP,DNS,ICMPv4,ICMPv6", Proto: true, AddContext: true,
			Buffer: true, MemBufferSize: 4096, NoOptCheck: true}})
	if err := c.CollectPcap(input); err != nil {
		t.Fatal(err)
	}
	if err := c.GetNetworkDetectionError(); err != nil {
		t.Fatal(err)
	}
	if s := c.PacketPipelineStats(); s.Rejected != 0 || s.Malformed != 0 || s.Incomplete != 0 {
		t.Fatalf("unhealthy normalization: %+v", s)
	}
}

func TestFragmentDetectionInterleavedCollector(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, base := range []int64{0, 1700000000} {
			for _, kind := range []string{"icmp", "dns", "tcp"} {
				t.Run(fmt.Sprintf("%s/v6=%t/epoch=%d", kind, v6, base), func(t *testing.T) {
					root := t.TempDir()
					dst := "10.0.0.2"
					if v6 {
						dst = "2001:db8::2"
					}
					options := networkdetect.DefaultConfig()
					options.ScanTargets = 2
					options.Indicators = []networkdetect.Indicator{{Kind: "ip", Value: dst, Category: "c2", Source: "fixture", Version: "1", ValidFrom: 0, ValidUntil: (base + 60) * 1e9}}
					data, err := json.Marshal(options)
					if err != nil {
						t.Fatal(err)
					}
					cfg := filepath.Join(root, "config.json")
					if err := os.WriteFile(cfg, data, 0600); err != nil {
						t.Fatal(err)
					}
					var reference *types.Alert
					for _, fragmented := range []bool{false, true} {
						var packets []behaviorPacket
						add := func(ip []byte, sec int64) {
							packets = append(packets, behaviorPacket{at: time.Unix(base+sec, 0), stack: []gopacket.SerializableLayer{gopacket.Payload(testutil.Ethernet(ip))}})
						}
						for i := 0; i < 2; i++ {
							var ip []byte
							switch kind {
							case "icmp":
								payload := []byte("interleaved echo evidence")
								protocol := layers.IPProtocolICMPv4
								echo := testutil.Serialize(&layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(8, 0), Id: 7, Seq: uint16(i)}, gopacket.Payload(payload))
								if v6 {
									protocol = layers.IPProtocolICMPv6
									echo = append([]byte{128, 0, 0, 0, 0, 7, 0, byte(i)}, payload...)
								}
								ip = testutil.IP(v6, false, protocol, echo)
								if i == 1 {
									if v6 {
										copy(ip[24:40], net.ParseIP("2001:db8::3").To16())
									} else {
										copy(ip[16:20], net.ParseIP("10.0.0.3").To4())
									}
								}
							case "dns":
								ip = testutil.IP(v6, false, layers.IPProtocolUDP, testutil.Serialize(&layers.UDP{SrcPort: 40000, DstPort: 53}, &layers.DNS{ID: uint16(i), Questions: []layers.DNSQuestion{{Name: []byte("api.telegram.org"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}}))
							case "tcp":
								ip = testutil.TCP(v6, false, uint32(i+1), 0, "S", "")
							}
							h := 20
							if v6 {
								h = 40
							}
							if fragmented {
								// Reverse fragment order on the second datagram; TCP's header is split.
								first := testutil.Fragment(ip, uint32(i+1), 0, 16, true)
								last := testutil.Fragment(ip, uint32(i+1), 16, len(ip)-h, false)
								if i == 1 {
									first, last = last, first
								}
								add(first, int64(i*3))
								add(testutil.TCP(v6, true, uint32(i+100), 0, "S", ""), int64(i*3+1))
								add(last, int64(i*3+2))
							} else {
								add(testutil.TCP(v6, true, uint32(i+100), 0, "S", ""), int64(i*3+1))
								add(ip, int64(i*3+2))
							}
						}
						input := filepath.Join(root, fmt.Sprintf("fragmented-%t.pcap", fragmented))
						writeBehaviorPCAP(t, input, packets)
						for _, workers := range []int{1, 4} {
							out := t.TempDir()
							exe, err := os.Executable()
							if err != nil {
								t.Fatal(err)
							}
							ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
							cmd := exec.CommandContext(ctx, exe, "-test.run=^TestFragmentDetectionProcess$", "-test.count=1")
							cmd.Env = append(os.Environ(), "NETCAP_FRAGMENT_DETECTION_INPUT="+input, "NETCAP_FRAGMENT_DETECTION_OUT="+out, "NETCAP_FRAGMENT_DETECTION_CONFIG="+cfg, fmt.Sprintf("NETCAP_FRAGMENT_DETECTION_WORKERS=%d", workers))
							output, err := cmd.CombinedOutput()
							cancel()
							if err != nil {
								t.Fatalf("fragmented=%t workers=%d: %v\n%s", fragmented, workers, err, output)
							}
							stats, err := networkdetect.ReadStats(filepath.Join(out, networkdetect.StatsFilename))
							if err != nil || stats.Events != 4 || stats.Late != 0 || stats.Alerts != 1 || stats.Error != "" {
								t.Fatalf("fragmented=%t workers=%d: stats=%+v err=%v", fragmented, workers, stats, err)
							}
							r, err := netio.Open(filepath.Join(out, "Alert.ncap.gz"), 4096)
							if err != nil {
								t.Fatal(err)
							}
							if _, err := r.ReadHeader(); err != nil {
								t.Fatal(err)
							}
							a := new(types.Alert)
							if err := r.Next(a); err != nil {
								t.Fatal(err)
							}
							if err := r.Next(new(types.Alert)); err != io.EOF {
								t.Fatal("unexpected extra alert", err)
							}
							r.Close()
							wantName, wantCount := "network.scan", uint64(1)
							if kind == "dns" {
								wantName, wantCount = "policy.telegram-api", 2
							} else if kind == "tcp" {
								wantName, wantCount = "intel.c2", 2
							}
							if a.Name != wantName || a.Count != wantCount || a.LastSeen != (base+5)*1e9 {
								t.Fatalf("unexpected detection semantics: %v", a)
							}
							if reference == nil {
								reference = a
							} else if !reflect.DeepEqual(reference, a) {
								t.Fatalf("fragmented=%t workers=%d changed detection evidence: %v != %v", fragmented, workers, a, reference)
							}
						}
					}
				})
			}
		}
	}
}
