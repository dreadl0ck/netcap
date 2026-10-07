package collector

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	cryptossh "golang.org/x/crypto/ssh"

	"github.com/dreadl0ck/netcap/internal/decoder/stream/tcp"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
)

func bookJSON[T any](t *testing.T, path string) T {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value T
	if err := json.Unmarshal(b, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

// Strict live-style parsing loses the offloaded transaction, but retention
// preserves its bytes. Offline tolerant reanalysis produces a new run and
// retains the derivative-to-source hash relationship rather than rewriting it.
func TestBookOfflineReanalysis(t *testing.T) {
	b, input := newBookCapture(t)
	request := "GET /recovered HTTP/1.1\r\nHost: lab.invalid\r\n\r\n"
	response := "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nLAB!"
	b.conversation("192.0.2.1", "198.51.100.1", 57000, 80, false, bookMessage{false, request}, bookMessage{true, response})
	b.conversation("192.0.2.2", "198.51.100.1", 57001, 80, true, bookMessage{false, request}, bookMessage{true, response})
	first := runBookCase(t, input, 4, true)
	before := bookRecords(t, first, "HTTP", func() *types.HTTP { return new(types.HTTP) })
	if len(before) != 1 {
		t.Fatalf("strict control=%d", len(before))
	}
	strict := bookJSON[tcp.ReassemblyHealth](t, filepath.Join(first, "TCPReassemblyHealth.json"))
	if strict.ChecksumPolicy != "strict" || strict.RejectedChecksums == 0 || len(strict.Limitations) == 0 {
		t.Fatalf("loss/policy unreported: %+v", strict)
	}
	source := bookJSON[evidence.CaptureManifest](t, filepath.Join(first, "capture-manifest.json"))
	if len(source.Segments) != 1 || source.Segments[0].State != "retained" {
		t.Fatalf("retained capture unavailable: %+v", source)
	}
	derivative := filepath.Join(first, source.Segments[0].Name)
	second := runBookCase(t, derivative, 2, false)
	after := bookRecords(t, second, "HTTP", func() *types.HTTP { return new(types.HTTP) })
	if len(after) != 2 {
		t.Fatal("offline recovery failed")
	}
	reanalysis := bookJSON[evidence.CaptureManifest](t, filepath.Join(second, "capture-manifest.json"))
	tolerant := bookJSON[tcp.ReassemblyHealth](t, filepath.Join(second, "TCPReassemblyHealth.json"))
	if reanalysis.RunID == source.RunID || reanalysis.InputSHA256 != source.Segments[0].SHA256 || reanalysis.IngressPackets != source.IngressPackets || tolerant.ChecksumPolicy != "tolerant" || tolerant.RejectedChecksums != 0 {
		t.Fatal("reanalysis provenance/policy lost")
	}
	bookStream(t, second, request, response)
	if len(bookRecords(t, first, "HTTP", func() *types.HTTP { return new(types.HTTP) })) != 1 {
		t.Fatal("reanalysis overwrote original evidence")
	}
}

// NSM's checksum case is an IPv4 offload trace, independently of TCP checksums.
func TestBookIPv4ChecksumOffload(t *testing.T) {
	b, input := newBookCapture(t)
	b.corruptIPv4Source = "198.51.100.2"
	request := "GET /ip-offload HTTP/1.1\r\nHost: lab.invalid\r\n\r\n"
	response := "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nLAB!"
	for i := range 2 {
		b.conversation("192.0.2.1", fmt.Sprintf("198.51.100.%d", i+1), uint16(57500+i), 80, false, bookMessage{false, request}, bookMessage{true, response})
	}
	for _, strict := range []bool{false, true} {
		t.Run(fmt.Sprint(strict), func(t *testing.T) {
			out := runBookCase(t, input, 4, strict)
			h := bookJSON[tcp.ReassemblyHealth](t, filepath.Join(out, "TCPReassemblyHealth.json"))
			if h.RejectedChecksums != 0 {
				t.Fatal("IPv4 corruption mislabeled as TCP checksum failure")
			}
			if strict && h.RejectedIPv4Checksums != 3 || !strict && h.RejectedIPv4Checksums != 0 {
				t.Fatalf("IPv4 discard count: %+v", h)
			}
			records := bookRecords(t, out, "HTTP", func() *types.HTTP { return new(types.HTTP) })
			success := 0
			for _, r := range records {
				if r.StatusCode == 200 {
					success++
					if strict && r.DstIP != "198.51.100.1" {
						t.Fatal("strict mode accepted offload response")
					}
				}
			}
			want := 2
			if strict {
				want = 1
			}
			if success != want {
				t.Fatalf("HTTP responses=%d want %d", success, want)
			}
			ips := bookRecords(t, out, "IPv4", func() *types.IPv4 { return new(types.IPv4) })
			zeros := 0
			for _, ip := range ips {
				if ip.Checksum == 0 {
					zeros++
				}
			}
			if len(ips) != b.n || zeros != 3 {
				t.Fatal("invalid IPv4 checksum packets lost as evidence")
			}
		})
	}
}

func TestBookSensorVantageAndRetention(t *testing.T) {
	request := "GET /vantage-marker HTTP/1.1\r\nHost: lab.invalid\r\n\r\n"
	response := "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nLAB!"
	var captures []evidence.CaptureManifest
	for i, src := range []string{"10.1.2.3", "192.0.2.254", "10.1.2.3"} {
		b, input := newBookCapture(t)
		if i == 2 {
			b.omitSource = "198.51.100.1"
		}
		b.conversation(src, "198.51.100.1", 60000, 80, false, bookMessage{false, request}, bookMessage{true, response})
		out := runBookCase(t, input, 2, false)
		m := bookJSON[evidence.CaptureManifest](t, filepath.Join(out, "capture-manifest.json"))
		captures = append(captures, m)
		if m.KernelDrops != nil || len(m.Segments) != 1 || m.Segments[0].State != "retained" {
			t.Fatal("offline sensor health invented kernel visibility or lost retention")
		}
		info, err := os.Stat(filepath.Join(out, m.Segments[0].Name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatal("retained packets are not private")
		}
		var records []*types.HTTP
		if _, err := os.Stat(filepath.Join(out, "HTTP.ncap")); i == 2 && os.IsNotExist(err) {
			h := bookJSON[tcp.ReassemblyHealth](t, filepath.Join(out, "TCPReassemblyHealth.json"))
			if h.RejectedFSM == 0 {
				t.Fatalf("missing asymmetric transactions without rejected-state evidence: %+v", h)
			}
		} else {
			records = bookRecords(t, out, "HTTP", func() *types.HTTP { return new(types.HTTP) })
		}
		if i < 2 {
			if len(records) != 1 || records[0].SrcIP != src || records[0].URL != "/vantage-marker" || records[0].StatusCode != 200 {
				t.Fatalf("vantage transaction: %v", records)
			}
			bookStream(t, out, request, response)
		} else {
			for _, r := range records {
				if r.StatusCode == 200 {
					t.Fatal("asymmetric sensor invented a response")
				}
			}
		}
		r := bookFlow(t, out, `InSubnet(SrcIP,"10.0.0.0/8")`, "srcIP")
		want := 1
		if i == 1 {
			want = 0
		}
		if r.Matched != want {
			t.Fatal("NAT-side selection conflated sensor identities")
		}
	}
	if captures[0].RunID == captures[1].RunID || captures[0].InputSHA256 == captures[1].InputSHA256 || captures[0].IngressPackets != 8 || captures[1].IngressPackets != 8 || captures[2].IngressPackets != 5 {
		t.Fatal("distributed/asymmetric capture identity and visibility ledger mismatch")
	}
}

// Uses the existing rule engine on collector output. IOC import success,
// an empty source, a nonmatching record, and source failure are distinct.
func TestBookDownloadIntelligenceIntegration(t *testing.T) {
	b, input := newBookCapture(t)
	body := string(bookExitELF(t))
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
	for i, host := range []string{"cdn.download.invalid", "evildownload.invalid", "ordinary.invalid"} {
		content := body
		if i == 2 {
			content = "benign nonmatching artifact"
		}
		request := fmt.Sprintf("GET http://%s/lab.bin HTTP/1.1\r\nHost: ignored.invalid\r\n\r\n", host)
		response := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Type: application/octet-stream\r\n\r\n%s", len(content), content)
		b.conversation("192.0.2.20", "198.51.100.20", uint16(58000+i), 8080, false, bookMessage{false, request}, bookMessage{true, response})
	}
	rulePath := filepath.Join(t.TempDir(), "indicators.yml")
	ruleText := fmt.Sprintf(`rules:
  - name: lab-domain-indicator-v1
    description: 'source=local-lab; type=domain; observation only, no execution claim'
    type: HTTP
    enabled: true
    severity: low
    expression: 'Host == "download.invalid" || Host endsWith ".download.invalid"'
    tags: [source:local-lab, indicator:domain, version:1]
  - name: lab-artifact-indicator-v1
    description: 'source=local-lab; type=sha256; download is not execution'
    type: File
    enabled: true
    severity: low
    expression: 'toJSON(Hashes) matches "\"SHA256\"[[:space:]]*:[[:space:]]*\"%s\""'
    tags: [source:local-lab, indicator:sha256, version:1]
`, digest)
	if err := os.WriteFile(rulePath, []byte(ruleText), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := rules.LoadRulesFromFile(rulePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := rules.CompileRules(cfg); err != nil {
		t.Fatal(err)
	}
	for _, workers := range []int{1, 4} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			out := runBookCase(t, input, workers, false)
			http := bookRecords(t, out, "HTTP", func() *types.HTTP { return new(types.HTTP) })
			files := bookRecords(t, out, "File", func() *types.File { return new(types.File) })
			if len(http) != 3 || len(files) != 3 {
				t.Fatal("missing download transactions/artifacts")
			}
			domainHits, fileHits := 0, 0
			var alerts []*types.Alert
			for _, r := range http {
				a, err := rules.EvaluateRule(cfg.Rules[0], r)
				if err != nil {
					t.Fatal(err)
				}
				if r.Host == "ignored.invalid" {
					t.Fatal("absolute proxy URI host was discarded")
				}
				if a != nil {
					domainHits++
					alerts = append(alerts, a)
					if r.Host != "cdn.download.invalid" || a.Timestamp != r.Timestamp || a.RuleDigest == "" || a.MatchedRecordSHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte(a.MatchedRecord))) {
						t.Fatalf("domain alert provenance: %v", a)
					}
				}
			}
			for _, f := range files {
				a, err := rules.EvaluateRule(cfg.Rules[1], f)
				if err != nil {
					t.Fatal(err)
				}
				if a != nil {
					fileHits++
					alerts = append(alerts, a)
					if f.Hashes == nil || f.Hashes.SHA256 != digest {
						t.Fatal("SHA256 rule matched a different artifact")
					}
				}
				if f.ConnectionUID == "" || f.CommunityID == "" || !f.IsComplete {
					t.Fatalf("artifact identity: %v", f)
				}
				linked := false
				for _, h := range http {
					if h.CommunityID == f.CommunityID {
						linked = true
					}
				}
				if !linked {
					t.Fatal("artifact has no transaction pivot")
				}
			}
			if domainHits != 1 || fileHits != 2 {
				t.Fatalf("domain/hash hits=%d/%d", domainHits, fileHits)
			}
			var alertData bytes.Buffer
			for _, a := range alerts {
				if err := json.NewEncoder(&alertData).Encode(a); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(out, "qualification-alerts.jsonl"), alertData.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(out, "indicator-source.yml"), []byte(ruleText), 0600); err != nil {
				t.Fatal(err)
			}
			connections := bookRecords(t, out, "Connection", func() *types.Connection { return new(types.Connection) })
			for _, f := range files {
				found := false
				for _, c := range connections {
					if c.CommunityID == f.CommunityID {
						found = true
						if c.ObservationID == "" || c.SnapshotSequence == 0 {
							t.Fatal("file/session pivot lacks exact identity")
						}
					}
				}
				if !found {
					t.Fatal("file session missing")
				}
			}
			archive, err := evidence.ArchiveToFile(context.Background(), input, filepath.Join(t.TempDir(), "selected.zip"), evidence.Selection{BPF: "tcp port 58000", MaxPackets: 100})
			if err != nil {
				t.Fatal(err)
			}
			if archive.Selected != 8 || archive.SourceSHA256 == "" || archive.OutputSHA256 == "" {
				t.Fatalf("alert-to-packet pivot: %+v", archive)
			}
		})
	}
	if _, err := rules.LoadRulesFromFile(filepath.Join(t.TempDir(), "missing.yml")); err == nil {
		t.Fatal("lookup failure interpreted as no data")
	}
	if err := os.WriteFile(rulePath, []byte("rules: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	empty, err := rules.LoadRulesFromFile(rulePath)
	if err != nil || len(empty.Rules) != 0 {
		t.Fatal("empty source fabricated indicators")
	}
}

type bookSSHWire struct {
	net.Conn
	server bool
	mu     *sync.Mutex
	trace  *[]bookMessage
}

func (c *bookSSHWire) Write(p []byte) (int, error) {
	c.mu.Lock()
	index := len(*c.trace)
	*c.trace = append(*c.trace, bookMessage{c.server, string(p)})
	c.mu.Unlock()
	n, err := c.Conn.Write(p)
	c.mu.Lock()
	(*c.trace)[index].text = string(p[:n])
	c.mu.Unlock()
	if n != len(p) && err == nil {
		err = io.ErrShortWrite
	}
	return n, err
}

// A real, authenticated loopback SSH transport. The server implements one
// in-memory channel; it never starts a shell or executes a process.
func bookEncryptedSSH(t *testing.T, secret []byte) []bookMessage {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptossh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var mu sync.Mutex
	var trace []bookMessage
	done := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		cfg := &cryptossh.ServerConfig{NoClientAuth: true}
		cfg.AddHostKey(signer)
		server, channels, requests, err := cryptossh.NewServerConn(&bookSSHWire{conn, true, &mu, &trace}, cfg)
		if err != nil {
			done <- err
			return
		}
		defer server.Close()
		go cryptossh.DiscardRequests(requests)
		incoming, ok := <-channels
		if !ok {
			done <- io.EOF
			return
		}
		if incoming.ChannelType() != "lab" {
			done <- fmt.Errorf("unexpected channel")
			return
		}
		ch, requests, err := incoming.Accept()
		if err != nil {
			done <- err
			return
		}
		defer ch.Close()
		go cryptossh.DiscardRequests(requests)
		got, err := io.ReadAll(ch)
		if err == nil && !bytes.Equal(got, secret) {
			err = fmt.Errorf("lab server received different plaintext")
		}
		if err == nil {
			_, err = ch.Write([]byte("LAB-ACK"))
		}
		done <- err
	}()
	conn, err := net.DialTimeout("tcp", l.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	client, channels, requests, err := cryptossh.NewClientConn(&bookSSHWire{conn, false, &mu, &trace}, l.Addr().String(), &cryptossh.ClientConfig{User: "lab", HostKeyCallback: cryptossh.FixedHostKey(signer.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	go cryptossh.DiscardRequests(requests)
	go func() {
		for ch := range channels {
			ch.Reject(cryptossh.UnknownChannelType, "no server channels")
		}
	}()
	ch, requests, err := client.OpenChannel("lab", nil)
	if err != nil {
		t.Fatal(err)
	}
	go cryptossh.DiscardRequests(requests)
	if _, err := ch.Write(secret); err != nil {
		t.Fatal(err)
	}
	if err := ch.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	ack, err := io.ReadAll(ch)
	if err != nil {
		t.Fatal(err)
	}
	if string(ack) != "LAB-ACK" {
		t.Fatal("encrypted channel acknowledgement missing")
	}
	ch.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	client.Close()
	mu.Lock()
	defer mu.Unlock()
	result := append([]bookMessage(nil), trace...)
	for _, m := range result {
		if bytes.Contains([]byte(m.text), secret) {
			t.Fatal("SSH fixture exposed plaintext on wire")
		}
	}
	return result
}

func TestBookLateralEncryptedTransfer(t *testing.T) {
	b, input := newBookCapture(t)
	packageBytes := string(bookExitELF(t))
	b.conversation("192.0.2.30", "198.51.100.30", 59000, 80, false, bookMessage{false, "GET /tunnel-tool HTTP/1.1\r\nHost: lab.invalid\r\n\r\n"}, bookMessage{true, fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(packageBytes), packageBytes)})
	secret := []byte("SYNTHETIC-LAB-TRANSFER-DO-NOT-INFER-FROM-SSH-METADATA")
	messages := bookEncryptedSSH(t, secret)
	b.conversation("192.0.2.30", "192.0.2.40", 59001, 22, false, messages...)
	inner := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(inner, gopacket.SerializeOptions{FixLengths: true}, &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4(10, 99, 0, 1), DstIP: net.IPv4(10, 99, 0, 2)}, &layers.UDP{SrcPort: 1234, DstPort: 4321}, gopacket.Payload("LAB-INNER")); err != nil {
		t.Fatal(err)
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(inner.Bytes())
	name := strings.ToLower(encoded[:40] + "." + encoded[40:] + ".tunnel.lab.invalid")
	dns := make([]byte, 12)
	binary.BigEndian.PutUint16(dns, 42)
	binary.BigEndian.PutUint16(dns[2:], 0x100)
	binary.BigEndian.PutUint16(dns[4:], 1)
	for _, label := range strings.Split(name, ".") {
		dns = append(dns, byte(len(label)))
		dns = append(dns, label...)
	}
	dns = append(dns, 0, 0, 10, 0, 1)
	b.udp("192.0.2.40", "198.51.100.53", 59002, 53, dns)
	dns[2], dns[3], dns[7] = 0x81, 0x80, 1
	answer := append([]byte{0xc0, 0x0c, 0, 10, 0, 1, 0, 0, 0, 60}, bookShorts(uint16(len(inner.Bytes())))...)
	answer = append(answer, inner.Bytes()...)
	b.udp("198.51.100.53", "192.0.2.40", 53, 59002, append(dns, answer...))
	benign := []byte{0, 43, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'w', 'w', 'w', 3, 'l', 'a', 'b', 7, 'i', 'n', 'v', 'a', 'l', 'i', 'd', 0, 0, 1, 0, 1}
	b.udp("192.0.2.40", "198.51.100.53", 59002, 53, benign)
	var client, server string
	for _, m := range messages {
		if m.server {
			server += m.text
		} else {
			client += m.text
		}
	}
	for _, workers := range []int{1, 4} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			out := runBookCase(t, input, workers, false)
			bookStream(t, out, client, server)
			files := bookRecords(t, out, "File", func() *types.File { return new(types.File) })
			if len(files) != 1 || files[0].Name != "tunnel-tool" {
				t.Fatalf("encrypted bytes invented an extracted file: %v", files)
			}
			r := bookFlow(t, out, `SrcIP == "192.0.2.30"`, "dstIP")
			if r.Matched != 2 || len(r.Groups) != 2 {
				t.Fatalf("package/lateral peer correlation: %+v", r)
			}
			for _, f := range files {
				data, err := os.ReadFile(f.Location)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(data, secret) {
					t.Fatal("encrypted plaintext unexpectedly extracted")
				}
			}
			dnsRecords := bookRecords(t, out, "DNS", func() *types.DNS { return new(types.DNS) })
			if len(dnsRecords) != 3 {
				t.Fatal("DNS tunnel/control transaction missing")
			}
			rule := &rules.Rule{Name: "lab DNS tunnel candidate", Type: "DNS", Expression: "!QR && QueryNameLength > 50", Description: "Long encoded query candidate; endpoint effects require external evidence", Severity: "low", Enabled: true}
			if err := rules.CompileRules(&rules.Config{Rules: []*rules.Rule{rule}}); err != nil {
				t.Fatal(err)
			}
			hits := 0
			found := false
			for _, d := range dnsRecords {
				a, err := rules.EvaluateRule(rule, d)
				if err != nil {
					t.Fatal(err)
				}
				if a != nil {
					hits++
					if a.Timestamp != d.Timestamp || a.MatchedRecordSHA256 == "" {
						t.Fatal("tunnel alert provenance")
					}
				}
				if d.QR {
					if len(d.Answers) != 1 || d.Answers[0].Type != 10 || !bytes.Equal(d.Answers[0].Data, inner.Bytes()) {
						t.Fatal("NULL tunnel payload changed")
					}
					found = true
				}
			}
			if hits != 1 || !found {
				t.Fatal("tunnel candidate or benign control failed")
			}
			r = bookFlow(t, out, `SrcIP == "192.0.2.40" || DstIP == "192.0.2.40"`, "protocol")
			if r.Matched != 2 || len(r.Groups) != 2 {
				t.Fatalf("SSH-to-outer-DNS pivot: %+v", r)
			}
			r = bookFlow(t, out, `InSubnet(SrcIP,"10.99.0.0/24") || InSubnet(DstIP,"10.99.0.0/24")`, "srcIP")
			if r.Matched != 0 {
				t.Fatal("inner tunnel addresses fabricated as sensor-observed flows")
			}
		})
	}
}
