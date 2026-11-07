//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestAuditSemanticsCLI(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	temp := t.TempDir()
	binaryPath := filepath.Join(temp, "net")
	build := exec.Command("go", "build", "-tags=nodpi,noyara,nomagika", "-o", binaryPath, "./cmd/net")
	build.Dir = root
	build.Env = append(os.Environ(), "GOWORK=off")
	if b, e := build.CombinedOutput(); e != nil {
		t.Fatalf("build: %v %s", e, b)
	}
	capture := filepath.Join(temp, "audit-semantics.pcap")
	writeAuditSemanticCapture(t, capture)
	required := []string{"HTTP", "DNS", "Kerberos", "TACACS", "IPP", "Zabbix", "Protobuf", "OPCUA", "S7Comm", "PROFINET", "RDP", "TLSCertificate"}
	var baseline map[string][]string
	for _, workers := range []int{1, 2, 4, 8} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "audit")
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binaryPath, "capture", "-read", capture, "-out", out, "-workers", fmt.Sprint(workers), "-include", strings.Join(append(required, "TCP", "Connection"), ","), "-context=true", "-capture-evidence=true", "-compress=false", "-dpi=false", "-geoDB=false", "-network-detection=false", "-fileStorage", "", "-http", "", "-quiet", "-y")
			cmd.Env = append(os.Environ(), "NC_CONFIG_ROOT="+filepath.Join(temp, "configuration"))
			if b, e := cmd.CombinedOutput(); e != nil {
				t.Fatalf("capture workers=%d: %v %s", workers, e, b)
			}
			connections := readSemanticRecords(t, out, "Connection")
			ids := map[string]bool{}
			for _, r := range connections {
				ids[r.(*types.Connection).CommunityID] = true
			}
			got := map[string][]string{}
			for _, name := range required {
				records := readSemanticRecords(t, out, name)
				if len(records) == 0 {
					t.Fatalf("required %s emitted no records", name)
				}
				for _, r := range records {
					v := reflect.ValueOf(r).Elem()
					cid := v.FieldByName("CommunityID").String()
					if cid == "" || !ids[cid] {
						t.Fatalf("%s record not linked to Connection: %s", name, cid)
					}
					if name == "HTTP" && cid != "1:/qFaeAR+gFe1KYjMzVDsMv+wgU4=" {
						t.Fatal("IPv6 extension-header HTTP differs from independent CommunityID vector", cid)
					}
					if name == "TLSCertificate" {
						c := r.(*types.TLSCertificate)
						if c.ValidityState != "valid" || c.AssessmentBasis != "capture-time" || c.AssessmentTime != c.Timestamp || !c.IsSelfSigned {
							t.Fatalf("certificate semantics: %+v", c)
						}
					}
					if name == "RDP" {
						c := r.(*types.RDP)
						if c.NegotiationOutcome != "accepted" || c.AuthenticationOutcome != "unknown" || !c.UsesTLS || c.UsesNLA || !c.NegotiatedSecurityKnown {
							t.Fatalf("RDP offer became login/security: %+v", c)
						}
					}
					h, row := r.CSVHeader(), r.CSVRecord()
					found := false
					for i, f := range h {
						if f == "CommunityID" && row[i] == cid {
							found = true
						}
					}
					if !found || len(h) != len(row) {
						t.Fatal("CSV lost correlation", name)
					}
					b, e := json.Marshal(r)
					if e != nil {
						t.Fatal(e)
					}
					got[name] = append(got[name], string(b))
				}
				sort.Strings(got[name])
			}
			peers := map[string]bool{}
			for _, r := range readSemanticRecords(t, out, "Protobuf") {
				peers[r.(*types.Protobuf).SrcIP] = true
			}
			if len(peers) != 2 {
				t.Fatal("protobuf response attributed to client")
			}
			senders := map[string]bool{}
			for _, r := range readSemanticRecords(t, out, "TLSCertificate") {
				senders[r.(*types.TLSCertificate).CertificateSender] = true
			}
			if !senders["client"] || !senders["server"] {
				t.Fatal("same certificate lost a mutual TLS sender")
			}
			if baseline == nil {
				baseline = got
			} else if !reflect.DeepEqual(baseline, got) {
				for name := range got {
					if !reflect.DeepEqual(baseline[name], got[name]) {
						t.Errorf("workers=%d changed %s semantics", workers, name)
					}
				}
			}
		})
	}
	oracle, err := exec.LookPath("tshark")
	if err != nil {
		t.Fatal("required audit-semantics oracle tshark missing", err)
	}
	version, err := exec.Command(oracle, "--version").Output()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(strings.SplitN(string(version), "\n", 2)[0])
	query := func(filter string, fields ...string) string {
		args := []string{"-n", "-r", capture, "-d", "tcp.port==25,http", "-Y", filter, "-T", "fields"}
		for _, f := range fields {
			args = append(args, "-e", f)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		b, e := exec.CommandContext(ctx, oracle, args...).CombinedOutput()
		if e != nil {
			t.Fatalf("tshark: %v %s", e, b)
		}
		return string(b)
	}
	if got := query("http.request", "http.request.method", "http.request.uri", "ipv6.src"); !strings.Contains(got, "GET\t/owned\t2001:470:e5bf:dead:4957:2174:e82c:4887") {
		t.Fatalf("independent HTTP fields disagree: %s", got)
	}
	if got := query("dns", "dns.qry.name"); !strings.Contains(got, "example.test") {
		t.Fatal("DNS framing oracle disagrees", got)
	}
	if got := query("tls.handshake.type == 11", "tls.handshake.type", "tcp.srcport"); !strings.Contains(got, "11\t443") || !strings.Contains(got, "11\t12345") {
		t.Fatal("TLS sender oracle disagrees", got)
	}
}

func readSemanticRecords(t *testing.T, out, name string) []types.AuditRecord {
	t.Helper()
	reader, err := netio.Open(filepath.Join(out, name+".ncap"), defaults.BufferSize)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	header, err := reader.ReadHeader()
	if err != nil {
		t.Fatal(err)
	}
	var records []types.AuditRecord
	for {
		r := netio.InitRecord(header.Type).(types.AuditRecord)
		err := reader.Next(r.(proto.Message))
		if err == io.EOF {
			return records
		}
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, r)
	}
}

func writeAuditSemanticCapture(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := pcapgo.NewWriterNanos(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	ordinal := 0
	flow := func(port layers.TCPPort, client, server []byte, ipv6 bool) {
		cseq, sseq := uint32(101), uint32(501)
		cport := layers.TCPPort(12345)
		if ipv6 {
			cport = 63943
		}
		emit := func(fromServer, syn, ack, fin bool, seq, an uint32, data []byte) {
			ipv4 := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(198, 51, 100, 1)}
			ip6 := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolTCP, SrcIP: net.ParseIP("2001:470:e5bf:dead:4957:2174:e82c:4887"), DstIP: net.ParseIP("2607:f8b0:400c:c03::1a")}
			tcp := &layers.TCP{SrcPort: cport, DstPort: port, Seq: seq, Ack: an, SYN: syn, ACK: ack, FIN: fin, Window: 4096}
			if fromServer {
				ipv4.SrcIP, ipv4.DstIP = ipv4.DstIP, ipv4.SrcIP
				ip6.SrcIP, ip6.DstIP = ip6.DstIP, ip6.SrcIP
				tcp.SrcPort, tcp.DstPort = tcp.DstPort, tcp.SrcPort
			}
			eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
			var network gopacket.SerializableLayer = ipv4
			if ipv6 {
				eth.EthernetType = layers.EthernetTypeIPv6
				network = ip6
				err = tcp.SetNetworkLayerForChecksum(ip6)
			} else {
				err = tcp.SetNetworkLayerForChecksum(ipv4)
			}
			if err != nil {
				t.Fatal(err)
			}
			b := gopacket.NewSerializeBuffer()
			if err := gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, network, tcp, gopacket.Payload(data)); err != nil {
				t.Fatal(err)
			}
			raw := b.Bytes()
			if ipv6 {
				extended := make([]byte, len(raw)+8)
				copy(extended, raw[:54])
				copy(extended[62:], raw[54:])
				extended[20] = 0
				extended[54] = 6
				binary.BigEndian.PutUint16(extended[18:], uint16(len(extended)-54))
				raw = extended
			}
			if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1590969600, int64(ordinal)*1_000_000), CaptureLength: len(raw), Length: len(raw)}, raw); err != nil {
				t.Fatal(err)
			}
			ordinal++
		}
		emit(false, true, false, false, 100, 0, nil)
		emit(true, true, true, false, 500, 101, nil)
		emit(false, false, true, false, cseq, sseq, nil)
		send := func(serverSide bool, data []byte) {
			for len(data) > 0 {
				n := min(37, len(data))
				if serverSide {
					emit(true, false, true, false, sseq, cseq, data[:n])
					sseq += uint32(n)
				} else {
					emit(false, false, true, false, cseq, sseq, data[:n])
					cseq += uint32(n)
				}
				data = data[n:]
			}
		}
		send(false, client)
		send(true, server)
		emit(false, false, true, true, cseq, sseq, nil)
		emit(true, false, true, true, sseq, cseq+1, nil)
		emit(false, false, true, false, cseq+1, sseq+1, nil)
	}
	flow(25, []byte("GET /owned HTTP/1.1\r\nHost: owned.example.test\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), true)
	flow(53, []byte{0, 30, 0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1}, nil, false)
	flow(49, append([]byte{0xc0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 12}, make([]byte, 12)...), nil, false)
	krb := append([]byte{0, 0, 1, 48, 0x6a, 0x82, 1, 44}, make([]byte, 300)...)
	flow(88, krb, nil, false)
	s7 := []byte{3, 0, 0, 19, 2, 0xf0, 0x80, 0x32, 1, 0, 0, 0, 0, 0, 2, 0, 0, 4, 0}
	flow(102, s7, nil, false)
	ipp := []byte{2, 0, 0, 2, 0, 0, 0, 1, 3}
	flow(631, append([]byte("POST /ipp/print HTTP/1.1\r\nContent-Type: application/ipp\r\nContent-Length: 9\r\n\r\n"), ipp...), nil, false)
	opc := append([]byte("HELF"), append([]byte{32, 0, 0, 0}, make([]byte, 24)...)...)
	flow(4840, opc, nil, false)
	pb := append([]byte{8, 0x96, 1, 0x12, 7}, []byte("testing")...)
	flow(9090, pb, pb, false)
	zb := []byte(`{"request":"active checks","host":"owned","key":"agent.ping"}`)
	z := append([]byte("ZBXD\x01"), make([]byte, 8)...)
	binary.LittleEndian.PutUint64(z[5:], uint64(len(zb)))
	flow(10050, append(z, zb...), nil, false)
	flow(34964, append([]byte{4, 0, 0, 0, 32, 0, 0, 0, 64, 0}, make([]byte, 32)...), nil, false)
	req := []byte{3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0}
	rsp := append([]byte(nil), req...)
	rsp[5] = 0xd0
	rsp[11] = 2
	rsp[15] = 1
	flow(3389, req, rsp, false)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, 32))
	cert := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "owned.example.test"}, NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	wrap := func(typ byte, body []byte) []byte {
		message := append([]byte{typ, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
		return append([]byte{22, 3, 3, byte(len(message) >> 8), byte(len(message))}, message...)
	}
	list := append([]byte{byte(len(der) >> 16), byte(len(der) >> 8), byte(len(der))}, der...)
	certMessage := wrap(11, append([]byte{byte(len(list) >> 16), byte(len(list) >> 8), byte(len(list))}, list...))
	clientHello := append([]byte{3, 3}, make([]byte, 32)...)
	clientHello = append(clientHello, 0, 0, 2, 0, 47, 1, 0)
	serverHello := append([]byte{3, 3}, make([]byte, 32)...)
	serverHello = append(serverHello, 0, 0, 47, 0)
	flow(443, append(wrap(1, clientHello), certMessage...), append(wrap(2, serverHello), certMessage...), false)
}
