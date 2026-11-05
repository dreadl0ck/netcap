package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/identity"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

// Opt-in corpus files stay outside git. No artifacts are extracted or executed.
func TestMTAReportRegressions(t *testing.T) {
	root := os.Getenv("NETCAP_MTA_ROOT")
	if root == "" {
		t.Skip("set NETCAP_MTA_ROOT to the checksum-pinned report corpus")
	}
	for _, tc := range []struct{ name, hash string }{
		{"2019-12-25-traffic-analysis-exercise.pcap", "a86c6a31ed04ed05571f997d296f8e7c7be7f262f6e602bd72d9e5de656945c5"},
		{"2019-08-20-traffic-analysis-exercise.pcap", "500da44cbb442f282549a28815bec1dc55e6c0120286c532c43f8dd4a8c5d94d"},
		{"2021-12-08-ISC-Forensic-Challenge.pcap", "91e547acc39e8ef27d7ec549404157fe527e090bd5caf6fe189c2bae6d4a57ef"},
		{"2024-07-30-traffic-analysis-exercise.pcap", "c48854c24223cf7b4e9880ea72a21a877e4138e4ce36df7b7656e5c6c4043f68"},
		{"2024-11-26-traffic-analysis-exercise.pcap", "a38267943a7bf3b0e445d7e51cb0a68b3dee797d67081bc9a033f73d079c0f50"},
		{"2026-09-11-traffic-analysis-exercise.pcap", "21bb800849459709a7ceb5513573b2b20f090ffccd00eb89b9886feedd47a2df"},
		{"2026-08-09-traffic-analysis-exercise.pcap", "0ea6b597732a9ce6af9a7e3adff4512c9a91b4bce27184c8fdeb746f05cce170"},
		{"2020-12-31-traffic-analysis-quiz-05.pcap", "7a063bb680dcf4af8fe3feaae873853a24ed287e4fdd390ecc70331d30784233"},
		{"2021-07-traffic-analysis-exercise.pcap", "a32fc4ce0496a2aec7ef4a8c80190a605d701afbe780ea62b5a58e929a2a72d0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := filepath.Join(root, tc.name)
			if _, err := os.Stat(input); os.IsNotExist(err) {
				input = filepath.Join(root, tc.name[:10], tc.name)
				if strings.HasPrefix(tc.name, "2021-07-") {
					input = filepath.Join(root, "2021-07-14", tc.name)
				}
			}
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
			if strings.HasPrefix(tc.name, "2019-12") {
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
			} else if strings.HasPrefix(tc.name, "2019-08") {
				count := 0
				read("TLSClientHello", func(m proto.Message) {
					r := m.(*types.TLSClientHello)
					if r.SNI == "mail.protonmail.com" && r.SrcIP == "5.39.113.142" {
						count++
					}
				})
				if count != 7 {
					t.Fatalf("reverse SOCKS TLS hellos: %d, want 7", count)
				}
			} else if strings.HasPrefix(tc.name, "2021-12") {
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
				tls := 0
				read("TLSClientHello", func(proto.Message) { tls++ })
				if tls != 209 {
					t.Fatalf("direct/STARTTLS hellos: %d, want 209", tls)
				}
			} else if strings.HasPrefix(tc.name, "2020") || strings.HasPrefix(tc.name, "2021-07") {
				observed := map[string]int{}
				read("HTTP", func(m proto.Message) {
					r := m.(*types.HTTP)
					if r.Method != "" {
						observed[r.Method+"\t"+r.URL+"\t"+r.SrcIP+"\t"+fmt.Sprint(r.SrcPort)]++
					}
				})
				if strings.HasPrefix(tc.name, "2021-07") {
					if observed["GET\t/\t81.17.23.125\t443"] < 1 || observed["GET\t/favicon.ico\t81.17.23.125\t443"] < 1 {
						t.Fatal("prefaced Dridex backconnect requests missing", observed)
					}
				}
				if tshark := os.Getenv("NETCAP_TSHARK"); tshark != "" {
					data, err := exec.Command(tshark, "-r", input, "-Y", "http.request && tcp", "-T", "fields", "-e", "http.request.method", "-e", "http.request.uri", "-e", "ip.src", "-e", "tcp.srcport").Output()
					if err != nil {
						t.Fatal(err)
					}
					expected := map[string]int{}
					for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
						expected[line]++
					}
					for tuple, n := range expected {
						if observed[tuple] < n {
							t.Fatal("reference HTTP request missing", tuple)
						}
					}
				}
			} else if strings.HasPrefix(tc.name, "2026") {
				account, full, ip := "gmcdowell", "Gabriel McDowell", "10.9.11.135"
				if strings.HasPrefix(tc.name, "2026-08") {
					account, full, ip = "rvance", "Raymond Vance", "172.16.8.49"
				}
				found := false
				read("DCERPC", func(m proto.Message) {
					for _, i := range m.(*types.DCERPC).Identities {
						if i.AccountName == account && i.FullName == full {
							found = true
						}
					}
				})
				if !found {
					t.Fatal("NDR64 SAMR full name missing")
				}
				data, err := os.ReadFile(filepath.Join(out, identity.Filename))
				if err != nil {
					t.Fatal(err)
				}
				var report identity.Report
				if err := json.Unmarshal(data, &report); err != nil {
					t.Fatal(err)
				}
				found = false
				for _, h := range report.Hosts {
					for _, a := range h.Accounts {
						if h.IP == ip && a.Name == account && a.FullName == full && len(a.FullNameEvidence) > 0 {
							found = true
						}
					}
				}
				if !found {
					t.Fatal("SAMR identity not retained with client-host provenance")
				}
			} else {
				full := map[string]bool{}
				read("LDAP", func(m proto.Message) {
					r := m.(*types.LDAP)
					values := map[string]string{}
					for _, a := range r.Attributes {
						if len(a.Values) == 1 {
							values[a.Name] = string(a.Values[0])
						}
					}
					name := values["displayName"]
					if name == "" {
						name = strings.TrimSpace(values["givenName"] + " " + values["sn"])
					}
					full[name] = true
				})
				if strings.HasPrefix(tc.name, "2024-07") {
					if !full["Clark Collier"] {
						t.Fatal("SASL-signed LDAP full name missing")
					}
				} else {
					if !full["Oliver Boomwald"] {
						t.Fatal("LDAP givenName/sn missing")
					}
					count := 0
					read("HTTP", func(m proto.Message) {
						r := m.(*types.HTTP)
						// The wire uses .64 and an absolute target; the report's .164 is a typo.
						if r.Method == "POST" && r.URL == "http://194.180.191.64/fakeurl.htm" && r.DstIP == "194.180.191.64" {
							count++
						}
					})
					if count != 58 {
						t.Fatalf("LF-only NetSupport requests: %d, want 58", count)
					}
				}
			}
			if tshark := os.Getenv("NETCAP_TSHARK"); tshark != "" {
				observed := map[string]int{}
				if _, err := os.Stat(filepath.Join(out, "TLSClientHello.ncap")); err == nil {
					read("TLSClientHello", func(m proto.Message) {
						r := m.(*types.TLSClientHello)
						observed[fmt.Sprintf("%s\t%d\t%s\t%d\t%s", r.SrcIP, r.SrcPort, r.DstIP, r.DstPort, r.SNI)]++
					})
				}
				data, err := exec.Command(tshark, "-r", input, "-Y", "tls.handshake.type==1 && tcp", "-T", "fields", "-e", "ip.src", "-e", "tcp.srcport", "-e", "ip.dst", "-e", "tcp.dstport", "-e", "tls.handshake.extensions_server_name").Output()
				if err != nil {
					t.Fatal(err)
				}
				expected := map[string]int{}
				if len(data) > 0 {
					for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
						expected[line]++
					}
				}
				for tuple, n := range expected {
					if observed[tuple] < n {
						t.Fatal("reference TLS hello missing", tuple)
					}
				}
			}
		})
	}
}
