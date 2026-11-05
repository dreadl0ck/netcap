package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

// Opt-in corpus files stay outside git. No artifacts are extracted or executed.
func TestMTAReportRegressions(t *testing.T) {
	root := os.Getenv("NETCAP_MTA_ROOT")
	if root == "" {
		t.Skip("set NETCAP_MTA_ROOT to the two checksum-pinned report captures")
	}
	for _, tc := range []struct{ name, hash string }{
		{"2019-12-25-traffic-analysis-exercise.pcap", "a86c6a31ed04ed05571f997d296f8e7c7be7f262f6e602bd72d9e5de656945c5"},
		{"2021-12-08-ISC-Forensic-Challenge.pcap", "91e547acc39e8ef27d7ec549404157fe527e090bd5caf6fe189c2bae6d4a57ef"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := filepath.Join(root, tc.name)
			f, err := os.Open(input)
			if err != nil {
				t.Fatal(err)
			}
			h := sha256.New()
			_, err = io.Copy(h, f)
			_ = f.Close()
			if err != nil || hex.EncodeToString(h.Sum(nil)) != tc.hash {
				t.Fatal("capture checksum mismatch", err)
			}
			out := t.TempDir()
			ultimateRun(t, input, out, 4, 0)
			read := func(kind string, fn func(proto.Message)) {
				r, err := netio.Open(filepath.Join(out, kind+".ncap"), 0)
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				header, err := r.ReadHeader()
				if err != nil {
					t.Fatal(err)
				}
				for {
					m := netio.InitRecord(header.Type)
					err = r.Next(m)
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
					fn(m)
				}
			}
			if strings.HasPrefix(tc.name, "2019") {
				requests, port, additional := 0, 0, 0
				observed := map[string]int{}
				read("HTTP", func(m proto.Message) {
					r := m.(*types.HTTP)
					if r.Method != "" {
						observed[r.Method+"\t"+r.URL+"\t"+r.SrcIP+"\t"+fmt.Sprint(r.SrcPort)]++
						requests++
						if r.SrcPort == 65134 {
							port++
						}
						if r.URL == "/s.php" && r.SrcPort == 60737 {
							additional++
						}
					}
				})
				// TShark 4.6.9 has 622 requests; frame 1437 also contains a complete POST /s.php.
				if requests != 623 || port != 21 || additional != 1 {
					t.Fatalf("HTTP: requests=%d port65134=%d additional_wire_POST=%d", requests, port, additional)
				}
				if tshark := os.Getenv("NETCAP_TSHARK"); tshark != "" {
					b, err := exec.Command(tshark, "-r", input, "-Y", "http.request", "-T", "fields", "-e", "http.request.method", "-e", "http.request.uri", "-e", "ip.src", "-e", "tcp.srcport").Output()
					if err != nil {
						t.Fatal(err)
					}
					expected := map[string]int{}
					for _, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
						expected[line]++
					}
					for tuple, n := range expected {
						if observed[tuple] < n {
							t.Fatal("reference HTTP transaction missing", tuple)
						}
					}
				}
				connections, packets := 0, int64(0)
				read("Connection", func(m proto.Message) { r := m.(*types.Connection); connections++; packets += r.NumPackets64 })
				if connections != 83 || packets != 2438 {
					t.Fatalf("flow totals: %d connections %d packets", connections, packets)
				}
			} else {
				auth := 0
				read("Secret", func(m proto.Message) {
					if strings.HasPrefix(m.(*types.Secret).Service, "SMTP Auth") {
						auth++
					}
				})
				pop := 0
				read("POP3", func(m proto.Message) {
					r := m.(*types.POP3)
					if r.ResponseStatus == "+OK" && r.ResponseText != "" {
						pop++
					}
				})
				if auth != 60 || pop != 242 {
					t.Fatalf("mail: %d AUTH exchanges %d populated POP3 sessions", auth, pop)
				}
				smtp := 0
				read("SMTP", func(m proto.Message) {
					if m.(*types.SMTP).ServerGreeting != "" {
						smtp++
					}
				})
				// Includes visible plaintext greetings on 2525/3535/465/5025.
				if smtp != 314 {
					t.Fatalf("populated SMTP sessions: %d", smtp)
				}
				if _, err := os.Stat(filepath.Join(out, "FTP.ncap")); !os.IsNotExist(err) {
					t.Fatal("SMTP capture produced FTP records")
				}
			}
		})
	}
}
