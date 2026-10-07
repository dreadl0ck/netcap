package collector

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/file"
	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/flow"
	"github.com/dreadl0ck/netcap/internal/flowexport"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
)

// All traffic is serialized locally; no socket, executable or book malware runs.
type bookCapture struct {
	t      *testing.T
	w      *pcapgo.Writer
	n      int
	offset time.Duration
}

func newBookCapture(t *testing.T) (*bookCapture, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "case.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	w := pcapgo.NewWriterNanos(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	return &bookCapture{t: t, w: w}, path
}

func (b *bookCapture) packet(src, dst string, tcp *layers.TCP, payload string, corrupt bool) int64 {
	b.t.Helper()
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP(src).To4(), DstIP: net.ParseIP(dst).To4()}
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		b.t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		b.t.Fatal(err)
	}
	data := buf.Bytes()
	if corrupt {
		data[14+20+16] ^= 0xff
	}
	ts := time.Unix(1700000000, int64(b.n)*100000+int64(b.offset))
	if err := b.w.WritePacket(gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(data), Length: len(data)}, data); err != nil {
		b.t.Fatal(err)
	}
	b.n++
	return ts.UnixNano()
}

type bookMessage struct {
	server bool
	text   string
}

func (b *bookCapture) udp(src, dst string, sport, dport uint16, payload []byte) {
	b.t.Helper()
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP(src).To4(), DstIP: net.ParseIP(dst).To4()}
	udp := &layers.UDP{SrcPort: layers.UDPPort(sport), DstPort: layers.UDPPort(dport)}
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		b.t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload(payload)); err != nil {
		b.t.Fatal(err)
	}
	data := buf.Bytes()
	if err := b.w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1700000000, int64(b.n)*100000+int64(b.offset)), CaptureLength: len(data), Length: len(data)}, data); err != nil {
		b.t.Fatal(err)
	}
	b.n++
}

func (b *bookCapture) openTCP(src, dst string, port, service uint16, corrupt bool) func(bool, bool, bool, string) int64 {
	seq, ack := uint32(1000), uint32(5000)
	send := func(reverse bool, syn, fin bool, payload string) int64 {
		s, d, sp, dp, sq, aq := src, dst, port, service, seq, ack
		if reverse {
			s, d, sp, dp, sq, aq = d, s, dp, sp, aq, sq
		}
		ts := b.packet(s, d, &layers.TCP{SrcPort: layers.TCPPort(sp), DstPort: layers.TCPPort(dp), Seq: sq, Ack: aq, SYN: syn, FIN: fin, ACK: !syn || reverse, PSH: payload != "", Window: 65535}, payload, corrupt)
		n := uint32(len(payload))
		if syn || fin {
			n++
		}
		if reverse {
			ack += n
		} else {
			seq += n
		}
		return ts
	}
	send(false, true, false, "")
	send(true, true, false, "")
	send(false, false, false, "")
	return send
}

func (b *bookCapture) conversation(src, dst string, port, service uint16, corrupt bool, messages ...bookMessage) []int64 {
	send := b.openTCP(src, dst, port, service, corrupt)
	var times []int64
	for _, m := range messages {
		times = append(times, send(m.server, false, false, m.text))
	}
	send(false, false, true, "")
	send(true, false, true, "")
	send(false, false, false, "")
	return times
}

func TestBookCaseProcess(t *testing.T) {
	input := os.Getenv("NETCAP_BOOK_INPUT")
	if input == "" {
		return
	}
	workers, err := strconv.Atoi(os.Getenv("NETCAP_BOOK_WORKERS"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := file.GetDefaultConfig()
	cfg.FileExtraction.Enabled = true
	cfg.FileExtraction.Protocols.HTTP = true
	cfg.FileExtraction.HashAlgorithms.SHA256 = true
	file.SetGlobalConfig(cfg)
	c := New(Config{Workers: workers, PacketBufferSize: 8, ReassembleConnections: true, CaptureEvidence: true, FlowExports: true, NoSignalHandling: true, NoPrompt: true, BaseLayer: layers.LayerTypeEthernet, DecodeOptions: gopacket.Default,
		DecoderConfig: &config.Config{Out: os.Getenv("NETCAP_BOOK_OUT"), Quiet: true, IncludeDecoders: "Connection,HTTP,FTP,File,TCP,DNS", Proto: true, Buffer: true, MemBufferSize: 4096, SaveConns: true, WaitForConnections: true, NoOptCheck: true, Checksum: os.Getenv("NETCAP_BOOK_STRICT") == "1", ClosePendingTimeOut: 5 * time.Second, CloseInactiveTimeOut: time.Minute, StreamBufferSize: 8, StreamDecoderBufSize: 8, NumStreamWorkers: 4, BannerSize: 256, FileStorage: "files", IncludePayloads: true}})
	c.config.DecoderConfig.WriteIncomplete = true
	if err := c.CollectPcap(input); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("NETCAP_BOOK_STRICT") == "1" {
		streamutils.Stats.Lock()
		rejects := streamutils.Stats.RejectOpt
		streamutils.Stats.Unlock()
		if rejects == 0 {
			t.Fatal("strict checksum rejection was not accounted")
		}
	}
}

func runBookCase(t *testing.T, input string, workers int, strict bool) string {
	t.Helper()
	out := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestBookCaseProcess$", "-test.timeout=60s")
	flag := "0"
	if strict {
		flag = "1"
	}
	cmd.Env = append(os.Environ(), "NETCAP_BOOK_INPUT="+input, "NETCAP_BOOK_OUT="+out, fmt.Sprintf("NETCAP_BOOK_WORKERS=%d", workers), "NETCAP_BOOK_STRICT="+flag)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("book replay: %v\n%s", err, output)
	}
	data, err := os.ReadFile(filepath.Join(out, "capture-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest evidence.CaptureManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	pcap, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Status != "done" || manifest.InputSHA256 != fmt.Sprintf("%x", sha256.Sum256(pcap)) || manifest.IngressPackets == 0 || manifest.IngressPackets != manifest.AdmittedPackets || manifest.QueueDrops != 0 {
		t.Fatalf("capture provenance: %+v", manifest)
	}
	return out
}

func bookRecords[T proto.Message](t *testing.T, out, name string, makeRecord func() T) []T {
	t.Helper()
	r, err := netio.Open(filepath.Join(out, name+".ncap"), 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.ReadHeader(); err != nil {
		t.Fatal(err)
	}
	var result []T
	for {
		record := makeRecord()
		err := r.Next(record)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, record)
	}
	return result
}

func bookStream(t *testing.T, out, client, server string) streamutils.StreamEvidenceManifest {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(out, "stream-evidence", "*", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var m streamutils.StreamEvidenceManifest
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatal(err)
		}
		c, err := os.ReadFile(filepath.Join(filepath.Dir(path), m.Client.Name))
		if err != nil {
			t.Fatal(err)
		}
		s, err := os.ReadFile(filepath.Join(filepath.Dir(path), m.Server.Name))
		if err != nil {
			t.Fatal(err)
		}
		if string(c) != client || string(s) != server {
			continue
		}
		if m.Client.SHA256 != fmt.Sprintf("%x", sha256.Sum256(c)) || m.Server.SHA256 != fmt.Sprintf("%x", sha256.Sum256(s)) || m.CommunityID == "" || m.Status != "no-reported-gap" {
			t.Fatalf("stream evidence: %+v", m)
		}
		return m
	}
	t.Fatalf("missing directional stream client=%q server=%q (%d manifests)", client, server, len(paths))
	return streamutils.StreamEvidenceManifest{}
}

// NSM pp. 214–223: an FTP marker is an attempt; only subsequent wire
// responses establish acceptance. The failed control remains a separate case.
func TestBookServerFTPTrigger(t *testing.T) {
	b, input := newBookCapture(t)
	for i := range 2 {
		src := fmt.Sprintf("192.0.2.%d", i+1)
		b.packet(src, "198.51.100.10", &layers.TCP{SrcPort: 40000, DstPort: 6200, Seq: 1, SYN: true}, "", false)
		b.packet("198.51.100.10", src, &layers.TCP{SrcPort: 6200, DstPort: 40000, Seq: 0, Ack: 2, RST: true, ACK: true}, "", false)
		b.conversation(src, "198.51.100.10", 40001, 21, false, bookMessage{true, "220 lab FTP\r\n"}, bookMessage{false, "USER fixture:)\r\n"}, bookMessage{true, "331 Password required\r\n"}, bookMessage{false, "PASS lab-only\r\n"}, bookMessage{true, "421 Timeout\r\n"})
		if i == 0 {
			b.conversation(src, "198.51.100.10", 40002, 6200, false, bookMessage{false, "id\n"}, bookMessage{true, "uid=0(lab) gid=0(lab)\n\x00\xff"})
		} else {
			b.packet(src, "198.51.100.10", &layers.TCP{SrcPort: 40002, DstPort: 6200, Seq: 1, SYN: true}, "", false)
			b.packet("198.51.100.10", src, &layers.TCP{SrcPort: 6200, DstPort: 40002, Ack: 2, RST: true, ACK: true}, "", false)
		}
	}
	for _, workers := range []int{1, 2, 4, 8} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			out := runBookCase(t, input, workers, false)
			records := bookRecords(t, out, "FTP", func() *types.FTP { return new(types.FTP) })
			if len(records) != 10 {
				t.Fatalf("FTP records=%d want 10", len(records))
			}
			users, replies := 0, 0
			triggers := map[string]int64{}
			for _, r := range records {
				if r.Timestamp%int64(time.Second) == 0 {
					t.Fatalf("lost subsecond provenance: %v", r)
				}
				if r.Command == "USER" {
					users++
					triggers[r.SrcIP] = r.Timestamp
					if r.Argument != "fixture:)" || r.Username != "fixture:)" {
						t.Fatalf("command state: %v", r)
					}
				}
				if r.IsResponse {
					replies++
					if r.SrcIP != "198.51.100.10" || r.SrcPort != 21 {
						t.Fatalf("response direction: %v", r)
					}
				}
			}
			if users != 2 || replies != 6 {
				t.Fatalf("users/replies=%d/%d", users, replies)
			}
			bookStream(t, out, "id\n", "uid=0(lab) gid=0(lab)\n\x00\xff")
			connections := bookRecords(t, out, "Connection", func() *types.Connection { return new(types.Connection) })
			if len(connections) != 6 {
				t.Fatalf("connections=%d want 6", len(connections))
			}
			for _, c := range connections {
				switch c.SrcPort {
				case "40000":
					if c.NumRSTFlags != 1 || c.TimestampLast >= triggers[c.SrcIP] {
						t.Fatalf("initial refusal chronology: %v", c)
					}
				case "40002":
					if c.TimestampFirst <= triggers[c.SrcIP] {
						t.Fatalf("follow-on precedes trigger: %v", c)
					}
					if c.SrcIP == "192.0.2.1" {
						if c.NumSYNFlags != 2 || c.NumRSTFlags != 0 {
							t.Fatalf("positive response missing: %v", c)
						}
					} else if c.NumRSTFlags != 1 || c.NumSYNFlags != 1 {
						t.Fatalf("failed control: %v", c)
					}
				}
			}
			q := flow.Query{StartNs: 1700000000000000000, EndNs: 1700000001000000000, Expression: `DstPort == "6200"`, GroupBy: "srcIP", SortBy: "bytes", Limit: 10}
			result, err := flow.ReadFile(context.Background(), filepath.Join(out, "Connection.ncap"), q)
			if err != nil {
				t.Fatal(err)
			}
			if result.Matched != 4 || len(result.Groups) != 2 || result.Groups[0].Key != "192.0.2.1" || result.Groups[0].Bytes <= result.Groups[1].Bytes {
				t.Fatalf("follow-on versus failed control: %+v", result)
			}
		})
	}
}

// NSM pp. 238–249 and 289–294: both proxy legs, redirect, binary download,
// callback and forged attribution header. Bytes alone do not prove execution.
func TestBookClientProxyDownload(t *testing.T) {
	b, input := newBookCapture(t)
	body := string(bookExitELF(t))
	request := "GET http://download.invalid/start HTTP/1.1\r\nHost: download.invalid\r\nX-Forwarded-For: 203.0.113.99\r\nVia: 1.1 lab-proxy\r\n\r\n"
	redirect := "HTTP/1.1 302 Found\r\nLocation: http://download.invalid/lab.bin\r\nContent-Length: 0\r\n\r\n"
	b.conversation("192.0.2.20", "192.0.2.254", 41000, 8080, false, bookMessage{false, request}, bookMessage{true, redirect})
	b.conversation("192.0.2.254", "198.51.100.20", 41001, 80, false, bookMessage{false, request}, bookMessage{true, redirect})
	b.conversation("192.0.2.20", "198.51.100.20", 41002, 80, false, bookMessage{false, "GET /lab.bin HTTP/1.1\r\nHost: download.invalid\r\n\r\n"}, bookMessage{true, fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n%s", len(body), body)})
	b.conversation("192.0.2.20", "203.0.113.20", 41003, 80, false, bookMessage{false, "POST /callback HTTP/1.1\r\nHost: callback.invalid\r\nContent-Length: 7\r\n\r\nLAB-ACK"}, bookMessage{true, "HTTP/1.1 204 No Content\r\n\r\n"})
	for _, workers := range []int{1, 2, 4, 8} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			out := runBookCase(t, input, workers, false)
			records := bookRecords(t, out, "HTTP", func() *types.HTTP { return new(types.HTTP) })
			if len(records) != 4 {
				t.Fatalf("HTTP records=%d want 4", len(records))
			}
			redirects, downloads, callbacks := 0, 0, 0
			for _, r := range records {
				switch r.StatusCode {
				case 302:
					redirects++
					if r.Host != "download.invalid" || r.XForwardedFor != "203.0.113.99" || r.SrcIP == r.XForwardedFor || r.RequestHeader["Via"] != "1.1 lab-proxy" || r.ResponseHeader["Location"] != "http://download.invalid/lab.bin" {
						t.Fatalf("proxy evidence: %v", r)
					}
				case 200:
					downloads++
					if r.URL != "/lab.bin" || r.ResContentLength != int32(len(body)) {
						t.Fatalf("download bytes: %v", r)
					}
				case 204:
					callbacks++
					if r.URL != "/callback" || r.ReqContentLength != 7 {
						t.Fatalf("callback: %v", r)
					}
				default:
					t.Fatalf("unexpected transaction: %v", r)
				}
			}
			if redirects != 2 || downloads != 1 || callbacks != 1 {
				t.Fatalf("chain=%d/%d/%d", redirects, downloads, callbacks)
			}
			files := bookRecords(t, out, "File", func() *types.File { return new(types.File) })
			found := false
			for _, f := range files {
				if f.Name == "lab.bin" {
					found = true
					want := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
					if f.Hashes == nil || f.Hashes.SHA256 != want || !f.IsComplete {
						t.Fatalf("file evidence: %v", f)
					}
					data, err := os.ReadFile(f.Location)
					if err != nil {
						t.Fatal(err)
					}
					if string(data) != body {
						t.Fatal("stored artifact differs from wire")
					}
				}
			}
			if !found {
				t.Fatalf("binary artifact missing: %v", files)
			}
			bookStream(t, out, "POST /callback HTTP/1.1\r\nHost: callback.invalid\r\nContent-Length: 7\r\n\r\nLAB-ACK", "HTTP/1.1 204 No Content\r\n\r\n")
		})
	}
}

// A complete Linux/amd64 ELF whose only code is exit(0). It is inspected as
// data, never executed; a magic prefix alone would not qualify a download.
func bookExitELF(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 129)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	put16 := func(at int, n uint16) { binary.LittleEndian.PutUint16(b[at:], n) }
	put32 := func(at int, n uint32) { binary.LittleEndian.PutUint32(b[at:], n) }
	put64 := func(at int, n uint64) { binary.LittleEndian.PutUint64(b[at:], n) }
	put16(16, 2)
	put16(18, 62)
	put32(20, 1)
	put64(24, 0x400078)
	put64(32, 64)
	put16(52, 64)
	put16(54, 56)
	put16(56, 1)
	put32(64, 1)
	put32(68, 5)
	put64(80, 0x400000)
	put64(88, 0x400000)
	put64(96, uint64(len(b)))
	put64(104, uint64(len(b)))
	put64(112, 4096)
	copy(b[120:], []byte{0xb8, 0x3c, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05})
	f, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if f.Type != elf.ET_EXEC || f.Entry != 0x400078 || len(f.Progs) != 1 {
		t.Fatal("invalid executable fixture")
	}
	return b
}

// NSM pp. 295–302: identical payloads with valid and corrupted TCP checksums.
// Strict rejection is not evidence of no traffic; packet records still exist.
func TestBookChecksumOffload(t *testing.T) {
	b, input := newBookCapture(t)
	request := "GET /offload HTTP/1.1\r\nHost: lab.invalid\r\n\r\n"
	response := "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nLAB"
	b.conversation("192.0.2.1", "198.51.100.1", 42000, 80, false, bookMessage{false, request}, bookMessage{true, response})
	b.conversation("192.0.2.2", "198.51.100.1", 42001, 80, true, bookMessage{false, request}, bookMessage{true, response})
	for _, strict := range []bool{false, true} {
		for _, workers := range []int{1, 4} {
			t.Run(fmt.Sprintf("strict=%v/workers=%d", strict, workers), func(t *testing.T) {
				out := runBookCase(t, input, workers, strict)
				records := bookRecords(t, out, "HTTP", func() *types.HTTP { return new(types.HTTP) })
				want := 2
				if strict {
					want = 1
				}
				if len(records) != want {
					t.Fatalf("transactions=%d want %d", len(records), want)
				}
				for _, r := range records {
					if r.StatusCode != 200 || strict && r.SrcIP != "192.0.2.1" {
						t.Fatalf("checksum policy: %v", r)
					}
				}
				packets := bookRecords(t, out, "TCP", func() *types.TCP { return new(types.TCP) })
				if len(packets) != b.n {
					t.Fatalf("invalid packets disappeared: %d want %d", len(packets), b.n)
				}
				bookStream(t, out, request, response)
			})
		}
	}
}

func TestBookIncompleteDownload(t *testing.T) {
	b, input := newBookCapture(t)
	body := string(bookExitELF(t)[:80])
	b.conversation("192.0.2.20", "198.51.100.20", 42010, 80, false, bookMessage{false, "GET /incomplete.bin HTTP/1.1\r\nHost: download.invalid\r\n\r\n"}, bookMessage{true, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 129\r\n\r\n" + body})
	for _, workers := range []int{1, 4} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			out := runBookCase(t, input, workers, false)
			files := bookRecords(t, out, "File", func() *types.File { return new(types.File) })
			if len(files) != 1 || files[0].IsComplete || files[0].CompletenessReason == "" || files[0].Length != 80 {
				t.Fatalf("truncation became a clean artifact: %v", files)
			}
			if files[0].Hashes == nil || files[0].Hashes.SHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte(body))) {
				t.Fatalf("partial bytes not retained: %v", files)
			}
		})
	}
}

// These qualify the raw/control evidence pivot, not automatic file extraction:
// FTP-DATA currently has no collector registration/caller.
func TestBookFTPControlDataEvidence(t *testing.T) {
	b, input := newBookCapture(t)
	archives := make([]string, 4)
	for i := range 4 {
		var buf bytes.Buffer
		z := zip.NewWriter(&buf)
		f, err := z.Create("lab.txt")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintf(f, "synthetic archive %d\x00\xff", i); err != nil {
			t.Fatal(err)
		}
		if err := z.Close(); err != nil {
			t.Fatal(err)
		}
		data := buf.String()
		archives[i] = data
		passive := i%2 == 0
		command := "RETR"
		if i >= 2 {
			command = "STOR"
		}
		client := fmt.Sprintf("192.0.2.%d", i+1)
		ip := "198.51.100.10"
		setup := []bookMessage{{true, "220 lab FTP\r\n"}, {false, "TYPE I\r\n"}, {true, "200 Binary\r\n"}}
		if passive {
			setup = append(setup, bookMessage{false, "PASV\r\n"}, bookMessage{true, "227 Passive (198,51,100,10,195,80)\r\n"})
		} else {
			ip = client
			setup = append(setup, bookMessage{false, fmt.Sprintf("PORT 192,0,2,%d,195,80\r\n", i+1)}, bookMessage{true, "200 PORT accepted\r\n"})
		}
		setup = append(setup, bookMessage{false, command + " lab.zip\r\n"}, bookMessage{true, "150 Opening data\r\n"})
		control := b.openTCP(client, "198.51.100.10", uint16(43000+i), 21, false)
		for _, m := range setup {
			control(m.server, false, false, m.text)
		}
		// Active FTP's TCP initiator is the FTP server, reversing stream roles.
		if passive {
			b.conversation(client, ip, uint16(44000+i), 50000, false, bookMessage{command == "RETR", data})
		} else {
			b.conversation("198.51.100.10", client, 20, 50000, false, bookMessage{command == "STOR", data})
		}
		control(true, false, false, "226 Transfer complete\r\n")
		control(false, false, true, "")
		control(true, false, true, "")
		control(false, false, false, "")
	}
	for _, workers := range []int{1, 2, 4, 8} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			out := runBookCase(t, input, workers, false)
			records := bookRecords(t, out, "FTP", func() *types.FTP { return new(types.FTP) })
			transfers, complete := 0, 0
			for _, r := range records {
				if r.Command == "RETR" || r.Command == "STOR" {
					transfers++
					if r.Filename != "lab.zip" || r.TransferMode != "BINARY" || r.DataPort != 50000 || r.DataConnectionMode == "UNKNOWN" {
						t.Fatalf("transfer association metadata: %v", r)
					}
				}
				if r.ResponseCode == 226 {
					complete++
					if r.Filename != "lab.zip" {
						t.Fatalf("completion metadata: %v", r)
					}
				}
			}
			if transfers != 4 || complete != 4 {
				t.Fatalf("transfers/completions=%d/%d", transfers, complete)
			}
			for i, data := range archives {
				client, server := data, ""
				if i == 0 || i == 3 {
					client, server = "", data
				}
				m := bookStream(t, out, client, server)
				if !strings.Contains(m.ConnectionKey, fmt.Sprintf("192.0.2.%d", i+1)) {
					t.Fatalf("archive associated with wrong peer: %+v", m)
				}
			}
		})
	}
}

// Flow Analysis pp. 93, 184–187: fan-out is a candidate; pivot without the
// initial SYN-only filter to find the responding service and benign server.
func TestBookFlowFanoutFailures(t *testing.T) {
	b, input := newBookCapture(t)
	for i := range 6 {
		b.packet("192.0.2.1", fmt.Sprintf("198.51.100.%d", i+1), &layers.TCP{SrcPort: 45000, DstPort: 445, Seq: 1, SYN: true}, "", false)
	}
	for i := range 4 {
		b.packet("192.0.2.2", "198.51.100.10", &layers.TCP{SrcPort: 45001, DstPort: layers.TCPPort(100 + i), Seq: 1, SYN: true}, "", false)
	}
	b.conversation("192.0.2.2", "198.51.100.10", 45002, 80, false, bookMessage{false, "GET / HTTP/1.1\r\nHost: lab.invalid\r\n\r\n"}, bookMessage{true, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"})
	for i := range 3 {
		b.conversation(fmt.Sprintf("192.0.2.%d", 10+i), "198.51.100.20", uint16(46000+i), 80, false, bookMessage{false, "GET / HTTP/1.1\r\nHost: lab.invalid\r\n\r\n"}, bookMessage{true, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"})
	}
	for _, workers := range []int{1, 2, 4, 8} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			out := runBookCase(t, input, workers, false)
			query := func(expr, group, sort string) flow.FileResult {
				t.Helper()
				result, err := flow.ReadFile(context.Background(), filepath.Join(out, "Connection.ncap"), flow.Query{StartNs: 1700000000000000000, EndNs: 1700000001000000000, Expression: expr, GroupBy: group, SortBy: sort, Limit: 100})
				if err != nil {
					t.Fatal(err)
				}
				return result
			}
			r := query("NumSYNFlags > 0 && NumACKFlags == 0", "srcIP", "peers")
			if r.Matched != 10 || len(r.Groups) != 2 || r.Groups[0].DistinctPeers != 6 || r.Groups[1].DistinctPeers != 1 {
				t.Fatalf("fanout: %+v", r)
			}
			r = query(`SrcIP == "192.0.2.2"`, "dstPort", "bytes")
			if len(r.Groups) != 5 || !strings.HasSuffix(r.Groups[0].Key, "80") {
				t.Fatalf("unfiltered responding-port pivot: %+v", r)
			}
			r = query(`DstIP == "198.51.100.20"`, "dstIP", "peers")
			if r.Matched != 3 || r.Groups[0].DistinctPeers != 3 {
				t.Fatalf("benign fan-in control: %+v", r)
			}
		})
	}
}

// NSM pp. 256–261: NULL answers preserve opaque bytes; an encoded label is
// correlated to the visible SSH peer, not decoded into invented inner traffic.
func TestBookDNSAndSSHCorrelation(t *testing.T) {
	b, input := newBookCapture(t)
	b.conversation("192.0.2.30", "192.0.2.40", 47000, 22, false, bookMessage{false, "SSH-2.0-lab-client\r\n"}, bookMessage{true, "SSH-2.0-lab-server\r\n"}, bookMessage{false, "\x00\x00\x00\x08\x04\x14\xa1\xb2\xc3\xd4\xe5\xf6"})
	for i, name := range []string{"ifbegrcfizduqskk.lab.invalid", "www.lab.invalid"} {
		dns := make([]byte, 12)
		binary.BigEndian.PutUint16(dns, uint16(100+i))
		binary.BigEndian.PutUint16(dns[2:], 0x0100)
		binary.BigEndian.PutUint16(dns[4:], 1)
		for _, label := range strings.Split(name, ".") {
			dns = append(dns, byte(len(label)))
			dns = append(dns, label...)
		}
		dns = append(dns, 0, 0, 10, 0, 1)
		if i == 1 {
			dns[len(dns)-3] = 1
		}
		b.udp("192.0.2.40", "198.51.100.53", uint16(48000+i), 53, dns)
		dns[2] = 0x81
		dns[3] = 0x80
		dns[7] = 1
		answer := []byte{0xc0, 0x0c, 0, 10, 0, 1, 0, 0, 0, 60, 0, 4, 0, 0xff, 0x80, 0x01}
		if i == 1 {
			answer[3] = 1
			copy(answer[12:], []byte{192, 0, 2, 80})
		}
		b.udp("198.51.100.53", "192.0.2.40", 53, uint16(48000+i), append(dns, answer...))
	}
	for _, workers := range []int{1, 2, 4, 8} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			out := runBookCase(t, input, workers, false)
			records := bookRecords(t, out, "DNS", func() *types.DNS { return new(types.DNS) })
			if len(records) != 4 {
				t.Fatalf("DNS records=%d want 4", len(records))
			}
			queries, answers := 0, 0
			for _, r := range records {
				if len(r.Questions) != 1 {
					t.Fatalf("DNS question lost: %v", r)
				}
				if r.Questions[0].Type != 10 {
					continue
				}
				if r.QR {
					answers++
					if len(r.Answers) != 1 || string(r.Answers[0].Data) != "\x00\xff\x80\x01" {
						t.Fatalf("NULL answer bytes: %v", r)
					}
				} else {
					queries++
				}
			}
			if queries != 1 || answers != 1 {
				t.Fatalf("NULL query/answer=%d/%d", queries, answers)
			}
			bookStream(t, out, "SSH-2.0-lab-client\r\n\x00\x00\x00\x08\x04\x14\xa1\xb2\xc3\xd4\xe5\xf6", "SSH-2.0-lab-server\r\n")
			result, err := flow.ReadFile(context.Background(), filepath.Join(out, "Connection.ncap"), flow.Query{StartNs: 1700000000000000000, EndNs: 1700000001000000000, Expression: `SrcIP == "192.0.2.40" || DstIP == "192.0.2.40"`, GroupBy: "protocol", SortBy: "bytes", Limit: 10})
			if err != nil {
				t.Fatal(err)
			}
			if result.Matched != 3 || len(result.Groups) != 2 {
				t.Fatalf("SSH and outer DNS visibility: %+v", result)
			}
		})
	}
}

// Flow Analysis pp. 99–112: real v5 datagrams through PCAP ingestion and
// report queries. Interface zero is a candidate, not proof of a firewall drop.
func TestBookFlowRoutingExports(t *testing.T) {
	b, input := newBookCapture(t)
	for i, route := range [][3]uint32{{1, 7, 0xc0000207}, {1, 8, 0xc0000208}, {7, 8, 0xc0000208}, {7, 0, 0}} {
		d := make([]byte, 24+48)
		binary.BigEndian.PutUint16(d, 5)
		binary.BigEndian.PutUint16(d[2:], 1)
		binary.BigEndian.PutUint32(d[4:], 120000)
		binary.BigEndian.PutUint32(d[8:], 1700000000)
		binary.BigEndian.PutUint32(d[16:], uint32(i))
		r := d[24:]
		copy(r, net.IPv4(192, 0, 2, 30).To4())
		copy(r[4:], net.IPv4(198, 51, 100, 10).To4())
		binary.BigEndian.PutUint32(r[8:], route[2])
		binary.BigEndian.PutUint16(r[12:], uint16(route[0]))
		binary.BigEndian.PutUint16(r[14:], uint16(route[1]))
		binary.BigEndian.PutUint32(r[16:], 10)
		binary.BigEndian.PutUint32(r[20:], uint32(1000*(i+1)))
		binary.BigEndian.PutUint32(r[24:], 100000+uint32(i*1000))
		binary.BigEndian.PutUint32(r[28:], 101000+uint32(i*1000))
		binary.BigEndian.PutUint16(r[32:], 49000)
		binary.BigEndian.PutUint16(r[34:], 443)
		r[37] = 0x12
		r[38] = 6
		binary.BigEndian.PutUint16(r[40:], 64512)
		binary.BigEndian.PutUint16(r[42:], 64513)
		r[44] = 24
		r[45] = 24
		b.udp("192.0.2.254", "192.0.2.253", 50000, 2055, d)
	}
	for _, workers := range []int{1, 2, 4, 8} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			out := runBookCase(t, input, workers, false)
			domain := uint32(0)
			q := flowexport.Query{StartNs: 1699999900000000000, EndNs: 1700000001000000000, TimeBasis: "flow", Exporter: "192.0.2.254:50000", Format: "netflow-v5", Domain: &domain, GroupBy: "ingressEgress", Limit: 10}
			read := func() flowexport.Report {
				t.Helper()
				r, err := flowexport.ReadReport(context.Background(), filepath.Join(out, "FlowExports.jsonl"), q)
				if err != nil {
					t.Fatal(err)
				}
				return r
			}
			r := read()
			if r.Matched != 4 || len(r.Groups) != 4 || r.Groups[0].Key != "7/0" || r.Groups[0].Bytes != 4000 {
				t.Fatalf("routing matrix: %+v", r)
			}
			ids := map[string]bool{}
			for _, g := range r.Groups {
				if len(g.Members) != 1 || ids[g.Members[0]] {
					t.Fatalf("nonexact report pivot: %+v", g)
				}
				ids[g.Members[0]] = true
			}
			zero := uint64(0)
			q.Egress = &zero
			r = read()
			if r.Matched != 1 || r.Groups[0].Key != "7/0" {
				t.Fatalf("interface zero candidate: %+v", r)
			}
			q.Egress = nil
			q.NextHop = "192.0.2.8"
			r = read()
			if r.Matched != 2 {
				t.Fatalf("next-hop pivot: %+v", r)
			}
			q.NextHop = ""
			q.GroupBy = "nextHop"
			q.StartNs, q.EndNs = 1699999980100000000, 1699999980900000000
			r = read()
			if r.Matched != 1 || r.Groups[0].Key != "192.0.2.7" {
				t.Fatalf("historical next-hop window: %+v", r)
			}
			q.StartNs, q.EndNs = 1699999900000000000, 1700000001000000000
			q.GroupBy = "dstPrefix"
			r = read()
			if len(r.Groups) != 1 || r.Groups[0].Key != "198.51.100.0/24" || r.Groups[0].Bytes != 10000 {
				t.Fatalf("exported prefix: %+v", r)
			}
			q.GroupBy = "dstAS"
			r = read()
			if len(r.Groups) != 1 || r.Groups[0].Key != "64513" {
				t.Fatalf("exported ASN: %+v", r)
			}
			q.Exporter = "192.0.2.252:50000"
			r = read()
			if r.Matched != 0 {
				t.Fatal("exporter scope leaked")
			}
		})
	}
}

// Flow Analysis pp. 83–99, 120–176: matched baseline scopes, recurrence,
// exact member pivots, and a graph explicitly estimating whole-flow volume.
func TestBookFlowBaselineAndSeries(t *testing.T) {
	b, input := newBookCapture(t)
	for i := range 4 {
		b.offset = time.Duration(i) * time.Second
		body := strings.Repeat("L", 200)
		if i == 3 {
			body = strings.Repeat("L", 1000)
		}
		b.conversation("192.0.2.20", "198.51.100.20", uint16(51000+i), 80, false, bookMessage{false, "GET /scheduled HTTP/1.1\r\nHost: lab.invalid\r\n\r\n"}, bookMessage{true, fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)})
	}
	for _, workers := range []int{1, 4} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			out := runBookCase(t, input, workers, false)
			q := flow.Query{StartNs: 1700000000000000000, EndNs: 1700000004000000000, Expression: `SrcIP == "192.0.2.20" && DstPort == "80"`, GroupBy: "srcIP", SortBy: "bytes", Limit: 10, BucketNs: int64(time.Second)}
			read := func() flow.FileResult {
				t.Helper()
				r, err := flow.ReadFile(context.Background(), filepath.Join(out, "Connection.ncap"), q)
				if err != nil {
					t.Fatal(err)
				}
				return r
			}
			r := read()
			if r.Matched != 4 || len(r.Groups) != 1 || len(r.Groups[0].Members) != 4 || len(r.Series) != 4 || r.Statistics.Bytes.Median != r.Statistics.Bytes.Min || r.Statistics.Bytes.Max <= r.Statistics.Bytes.Median {
				t.Fatalf("baseline/recurrence: %+v", r)
			}
			var sum float64
			for _, bin := range r.Series {
				sum += bin.EstimatedBytes
				if !bin.DirectionalComplete || bin.EstimatedServerBytes <= bin.EstimatedClientBytes || math.Abs(bin.EstimatedBytes-bin.EstimatedClientBytes-bin.EstimatedServerBytes) > 1e-6 {
					t.Fatalf("directional series: %+v", bin)
				}
			}
			if math.Abs(sum-float64(r.Groups[0].Bytes)) > 1e-6 || r.Groups[0].BytePercent != 100 {
				t.Fatalf("series/share accounting: %+v", r)
			}
			// Same endpoint/service and duration: three ordinary one-second windows
			// versus the fourth; compare distributions rather than raw file totals.
			q.EndNs = q.StartNs + int64(time.Second)
			base := read()
			q.StartNs += 3 * int64(time.Second)
			q.EndNs = q.StartNs + int64(time.Second)
			changed := read()
			if base.Matched != 1 || changed.Matched != 1 || changed.Statistics.Bytes.Min <= base.Statistics.Bytes.Max {
				t.Fatal("matched-scope baseline did not expose the larger transfer")
			}
			// A display slice through a flow excludes it under contained/start/end,
			// but overlap keeps exact whole-flow counters and clips the estimate.
			q.StartNs = 1700000000000100000
			q.EndNs = 1700000000000600000
			q.BucketNs = 100000
			q.WindowMode = "overlap"
			overlap := read()
			if overlap.Matched != 1 {
				t.Fatal("overlap missing")
			}
			var clipped float64
			for _, bin := range overlap.Series {
				clipped += bin.EstimatedBytes
			}
			if clipped <= 0 || clipped >= float64(overlap.Groups[0].Bytes) {
				t.Fatal("display clipping altered whole-flow semantics")
			}
			for _, mode := range []string{"contained", "start", "end"} {
				q.WindowMode = mode
				if read().Matched != 0 {
					t.Fatalf("%s silently behaved as overlap", mode)
				}
			}
		})
	}
}
