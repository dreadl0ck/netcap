package tcp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/dreadl0ck/netcap/internal/decoder"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/ftp"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/imap"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/smtp"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/ssh"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
)

// Fetch only the pinned URLs in testdata/round2.json into NETCAP_W76_TCP_FIXTURES.
// Nothing is downloaded by tests, and payloads are never extracted or executed.
func TestRound2PinnedCaptures(t *testing.T) {
	dir := os.Getenv("NETCAP_W76_TCP_FIXTURES")
	if dir == "" {
		t.Skip("set NETCAP_W76_TCP_FIXTURES to the reviewed capture directory")
	}
	manifest, err := os.ReadFile("testdata/round2.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct{ File, URL, SHA256, Protocol string }
	if err := json.Unmarshal(manifest, &fixtures); err != nil {
		t.Fatal(err)
	}
	decoders := map[string]*decoder.StreamDecoder{"SSH": ssh.Decoder, "IMAP": imap.Decoder, "SMTP": smtp.Decoder, "FTP": ftp.Decoder, "wire": imap.Decoder}
	for _, fixture := range fixtures {
		for _, dropSYN := range []bool{false, true} {
			if dropSYN && fixture.Protocol != "IMAP" {
				continue
			}
			name := fixture.File
			if dropSYN {
				name += "/no-client-SYN"
			}
			t.Run(name, func(t *testing.T) {
				wire, err := os.ReadFile(filepath.Join(dir, fixture.File))
				if err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(wire)
				if hex.EncodeToString(sum[:]) != fixture.SHA256 {
					t.Fatal("fixture hash mismatch")
				}
				w := round2Config(t, decoders[fixture.Protocol])
				f := &round2Factory{}
				a := reassembly.NewAssembler(reassembly.NewStreamPool(f))
				reader, err := pcapgo.NewReader(bytes.NewReader(wire))
				if err != nil {
					t.Fatal(err)
				}
				for {
					data, ci, err := reader.ReadPacketData()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
					p := gopacket.NewPacket(data, reader.LinkType(), gopacket.Default)
					layer := p.Layer(layers.LayerTypeTCP)
					if layer == nil || p.NetworkLayer() == nil {
						continue
					}
					tcp := layer.(*layers.TCP)
					if dropSYN && tcp.SYN && !tcp.ACK {
						continue
					}
					a.AssembleWithContext(p.NetworkLayer().NetworkFlow(), tcp, &context{CaptureInfo: ci})
				}
				a.FlushAll()
				observed, qualified := 0, 0
				needle, reason, wantObserved, wantQualified := "GET /ultrasurf.html", "after-rst", 1, 1
				if fixture.File == "bug-3286-02.pcap" {
					needle = "GET /"
				}
				if fixture.File == "egypt-packetlogic-ttl-localization.pcap" {
					needle, reason, wantObserved, wantQualified = "GET /", "after-fin", 38, 19
				}
				for _, s := range f.streams {
					if s.complete != 1 {
						t.Fatalf("completion count %d", s.complete)
					}
					for _, d := range s.merged {
						if bytes.Contains(d.Raw(), []byte(needle)) {
							observed++
							if d.(*core.StreamData).TCPObservation == reason {
								qualified++
							}
						}
					}
				}
				if fixture.Protocol == "wire" {
					if observed != wantObserved || qualified != wantQualified {
						t.Fatalf("continuation: observed=%d qualified=%d, want %d/%d", observed, qualified, wantObserved, wantQualified)
					}
				} else if fixture.Protocol == "SMTP" || fixture.Protocol == "FTP" {
					// These captures contain only QUIT after the peer's FIN, no
					// greeting. Selection requires stronger protocol evidence.
					if len(f.streams) != 1 || string(f.streams[0].client.DataSlice().Bytes()) != "QUIT\r\n" {
						t.Fatal("half-close lost the observed QUIT command")
					}
					t.Logf("selection gap: %s QUIT-only stream, application records=%d", fixture.Protocol, len(w.records))
				} else {
					want := map[string]int{"ssh-client.pcap": 20, "ssh-server.pcap": 20, "imap-detection.pcap": 357, "tcp-async-01.pcap": 62}[fixture.File]
					if len(w.records) != want {
						t.Fatalf("records=%d want=%d", len(w.records), want)
					}
				}
				for _, record := range w.records {
					if m, ok := record.(*types.SSH); ok {
						if m.IsClient != (fixture.File == "ssh-client.pcap") || m.Ident == "" {
							t.Fatal("SSH role or ident lost")
						}
					}
				}
				t.Logf("records=%d connections=%d qualifiedRequests=%d", len(w.records), len(f.streams), qualified)
			})
		}
	}
}
