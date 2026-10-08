package collector

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/stream/ftp"
	"github.com/dreadl0ck/netcap/internal/flow"
	"github.com/dreadl0ck/netcap/internal/flowexport"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func (b *bookCapture) network(src, dst string, protocol layers.IPProtocol, payload []byte) {
	b.t.Helper()
	s, d := net.ParseIP(src), net.ParseIP(dst)
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
	var ip gopacket.SerializableLayer = &layers.IPv4{Version: 4, TTL: 64, Protocol: protocol, SrcIP: s.To4(), DstIP: d.To4()}
	if s.To4() == nil {
		eth.EthernetType = layers.EthernetTypeIPv6
		ip = &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: protocol, SrcIP: s, DstIP: d}
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, gopacket.Payload(payload)); err != nil {
		b.t.Fatal(err)
	}
	data := buf.Bytes()
	if err := b.w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1700000000, int64(b.n)*100000+int64(b.offset)), CaptureLength: len(data), Length: len(data)}, data); err != nil {
		b.t.Fatal(err)
	}
	b.n++
}

func bookFlow(t *testing.T, out, expr, group string) flow.FileResult {
	t.Helper()
	r, err := flow.ReadFile(context.Background(), filepath.Join(out, "Connection.ncap"), flow.Query{StartNs: 1699999999000000000, EndNs: 1700000100000000000, Expression: expr, GroupBy: group, SortBy: "bytes", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestBookFTPAttributionBoundaries(t *testing.T) {
	b, input := newBookCapture(t)
	for i := range 9 {
		client := fmt.Sprintf("192.0.2.%d", i+50)
		control := b.openTCP(client, "198.51.100.10", uint16(52000+i), 21, false)
		control(true, false, false, "220 lab FTP\r\n")
		if i == 5 {
			control(false, false, false, "PROT P\r\n")
			control(true, false, false, "200 Protected data\r\n")
		}
		control(false, false, false, "PASV\r\n")
		endpoint := "227 Passive (198,51,100,10,195,80)\r\n"
		if i == 8 {
			endpoint = "227 Passive (203,0,113,10,195,80)\r\n"
		}
		control(true, false, false, endpoint)
		if i == 4 { // A previous connection at the endpoint must not match a later RETR.
			b.conversation(client, "198.51.100.10", uint16(53000+i), 50000, false, bookMessage{true, "STALE"})
		}
		control(false, false, false, fmt.Sprintf("RETR case-%d.bin\r\n", i))
		if i == 3 {
			control(true, false, false, "550 Denied\r\n")
		} else {
			control(true, false, false, "150 Opening\r\n")
		}
		peer := client
		if i == 2 {
			peer = "192.0.2.200"
		}
		if i != 4 {
			b.conversation(peer, "198.51.100.10", uint16(53000+i), 50000, false, bookMessage{i != 7, fmt.Sprintf("CASE-%d\x00\xff", i)})
		}
		if i == 6 {
			b.conversation(peer, "198.51.100.10", 54000, 50000, false, bookMessage{true, "AMBIGUOUS"})
		}
		if i == 1 {
			control(true, false, false, "426 Transfer aborted\r\n")
		} else {
			control(true, false, false, "226 Complete\r\n")
		}
		control(false, false, true, "")
		control(true, false, true, "")
		control(false, false, false, "")
	}
	for _, workers := range []int{1, 2, 4, 8} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			out := runBookCase(t, input, workers, false)
			files := bookRecords(t, out, "File", func() *types.File { return new(types.File) })
			if len(files) != 2 {
				t.Fatalf("unrelated/refused/encrypted/ambiguous data attributed: %v", files)
			}
			for _, f := range files {
				switch f.Name {
				case "case-0.bin":
					if !f.IsComplete {
						t.Fatalf("complete transfer: %v", f)
					}
				case "case-1.bin":
					if f.IsComplete || f.CompletenessReason == "" {
						t.Fatalf("aborted transfer marked complete: %v", f)
					}
				default:
					t.Fatalf("unrelated transfer: %v", f)
				}
			}
			data, err := os.ReadFile(filepath.Join(out, "FTPDataHealth.json"))
			if err != nil {
				t.Fatal(err)
			}
			var h ftp.DataHealth
			if err := json.Unmarshal(data, &h); err != nil {
				t.Fatal(err)
			}
			if len(h.Associations) != 2 || h.Ambiguous != 2 || h.Status != "partial" || h.Rejected != 0 || h.UnsupportedEndpoints != 1 || h.UnmatchedTransfers != 3 {
				t.Fatalf("association accounting: %+v", h)
			}
			for _, a := range h.Associations {
				if a.ControlKey == "" || a.DataKey == "" || a.StartNs == 0 || a.EndNs < a.StartNs || len(a.SHA256) != 64 {
					t.Fatalf("inexact FTP association: %+v", a)
				}
				found := false
				for _, f := range files {
					if f.CommunityID == a.DataCommunityID && f.Hashes != nil && f.Hashes.SHA256 == a.SHA256 {
						found = true
					}
				}
				if !found {
					t.Fatal("association has no exact file hash pivot")
				}
			}
		})
	}
}

func TestBookICMPAndServerRecon(t *testing.T) {
	b, input := newBookCapture(t)
	inner := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(inner, gopacket.SerializeOptions{FixLengths: true}, &layers.IPv4{Version: 4, TTL: 1, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(198, 51, 100, 10)}, &layers.UDP{SrcPort: 55000, DstPort: 33434}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range [][2]uint8{{8, 0}, {0, 0}, {3, 3}, {3, 4}, {11, 0}} {
		payload := []byte("RECON-LAB")
		src, dst := "192.0.2.1", "198.51.100.10"
		if tc[0] != 8 {
			src, dst = dst, src
		}
		if tc[0] == 3 || tc[0] == 11 {
			payload = inner.Bytes()
		}
		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true}, &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(tc[0], tc[1]), Id: 10, Seq: 1}, gopacket.Payload(payload)); err != nil {
			t.Fatal(err)
		}
		b.network(src, dst, layers.IPProtocolICMPv4, buf.Bytes())
	}
	for _, port := range []layers.TCPPort{21, 22, 80, 443} {
		b.packet("192.0.2.1", "198.51.100.10", &layers.TCP{SrcPort: 55000, DstPort: port, Seq: 1, SYN: true}, "", false)
	}
	b.packet("198.51.100.10", "192.0.2.1", &layers.TCP{SrcPort: 25, DstPort: 55001, RST: true}, "", false)
	b.packet("198.51.100.10", "192.0.2.1", &layers.TCP{SrcPort: 26, DstPort: 55003, RST: true, ACK: true}, "", false)
	b.conversation("192.0.2.1", "198.51.100.10", 55002, 21, false, bookMessage{true, "220 Recon FTP\r\n"}, bookMessage{false, "SYST\r\n"}, bookMessage{true, "215 UNIX lab\r\n"})
	ledger := bookWireCounts(t, input)
	for _, workers := range []int{1, 2, 4, 8} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			out := runBookCase(t, input, workers, false)
			records := bookRecords(t, out, "ICMPv4", func() *types.ICMPv4 { return new(types.ICMPv4) })
			if len(records) != 5 {
				t.Fatalf("ICMP records=%d", len(records))
			}
			seen := map[string]bool{}
			for _, r := range records {
				seen[fmt.Sprintf("%d/%d", r.Type, r.Code)] = true
				if r.Type == 3 || r.Type == 11 {
					if !bytes.Equal(r.Payload, inner.Bytes()) {
						t.Fatal("quoted related datagram changed")
					}
					quoted := gopacket.NewPacket(r.Payload, layers.LayerTypeIPv4, gopacket.Default)
					ip := quoted.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
					if ip.SrcIP.String() != "192.0.2.1" || ip.DstIP.String() != "198.51.100.10" {
						t.Fatal("wrong related endpoints")
					}
				}
			}
			for _, key := range []string{"8/0", "0/0", "3/3", "3/4", "11/0"} {
				if !seen[key] {
					t.Fatal("missing ICMP distinction", key)
				}
			}
			r := bookFlow(t, out, `NumSYNFlags > 0 && NumACKFlags == 0`, "dstPort")
			if r.Matched != 4 || len(r.Groups) != 4 {
				t.Fatalf("recon port sweep: %+v", r)
			}
			limited, err := flow.ReadFile(context.Background(), filepath.Join(out, "Connection.ncap"), flow.Query{StartNs: 1699999999000000000, EndNs: 1700000100000000000, Expression: `NumSYNFlags > 0 && NumACKFlags == 0`, GroupBy: "dstPort", SortBy: "bytes", Limit: 1})
			if err != nil {
				t.Fatal(err)
			}
			if len(limited.Groups) != 1 || limited.TotalGroups != 4 || limited.Matched != r.Matched {
				t.Fatal("limited recon result silently claimed pagination completeness")
			}
			pages := map[string]flow.Group{}
			page := limited
			for {
				for _, g := range page.Groups {
					if _, duplicate := pages[g.Key]; duplicate {
						t.Fatal("duplicate group across recon pages")
					}
					pages[g.Key] = g
				}
				if page.NextOffset == nil {
					break
				}
				q := page.Query
				q.Offset = *page.NextOffset
				q.ExpectedSHA256 = limited.RecordFileSHA256
				page, err = flow.ReadFile(context.Background(), filepath.Join(out, "Connection.ncap"), q)
				if err != nil {
					t.Fatal(err)
				}
			}
			if len(pages) != len(r.Groups) {
				t.Fatal("pagination did not retrieve entire recon sweep")
			}
			for _, g := range r.Groups {
				got := pages[g.Key]
				if len(got.Members) != 1 || got.Members[0] != g.Members[0] || got.Bytes != g.Bytes || got.Packets != g.Packets {
					t.Fatal("paginated recon member differs from full result")
				}
			}
			q := limited.Query
			q.Offset = 1
			q.ExpectedSHA256 = strings.Repeat("0", 64)
			if _, err := flow.ReadFile(context.Background(), filepath.Join(out, "Connection.ncap"), q); err == nil {
				t.Fatal("pagination accepted a different source snapshot")
			}
			q.ExpectedSHA256 = ""
			if _, err := flow.ReadFile(context.Background(), filepath.Join(out, "Connection.ncap"), q); err == nil {
				t.Fatal("pagination accepted an unbound source")
			}
			r = bookFlow(t, out, `NumRSTFlags > 0 && NumSYNFlags == 0 && NumACKFlags == 0 && NumFINFlags == 0 && NumPSHFlags == 0`, "srcIP")
			if r.Matched != 1 {
				t.Fatalf("RST-only filter: %+v", r)
			}
			ftpRecords := bookRecords(t, out, "FTP", func() *types.FTP { return new(types.FTP) })
			if len(ftpRecords) != 3 || ftpRecords[0].Timestamp <= records[4].Timestamp {
				t.Fatal("ICMP/service chronology or transaction completeness")
			}
			icmpLast := int64(0)
			for _, r := range records {
				icmpLast = max(icmpLast, r.Timestamp)
			}
			portsFirst, portsLast, serviceFirst := int64(1<<63-1), int64(0), int64(1<<63-1)
			tcps := bookRecords(t, out, "TCP", func() *types.TCP { return new(types.TCP) })
			for _, r := range tcps {
				if r.SrcPort == 55002 || r.DstPort == 55002 {
					serviceFirst = min(serviceFirst, r.Timestamp)
				} else {
					portsFirst = min(portsFirst, r.Timestamp)
					portsLast = max(portsLast, r.Timestamp)
				}
			}
			if !(icmpLast < portsFirst && portsLast < serviceFirst && serviceFirst < ftpRecords[0].Timestamp) {
				t.Fatal("ICMP -> port -> service handshake -> banner temporal order failed")
			}
			got := map[string]bookWireCount{}
			connections := bookRecords(t, out, "Connection", func() *types.Connection { return new(types.Connection) })
			for _, c := range connections {
				for _, d := range []struct {
					ip             string
					packets, bytes int64
				}{{c.SrcIP, c.PacketsClientToServer, c.BytesClientToServer}, {c.DstIP, c.PacketsServerToClient, c.BytesServerToClient}} {
					key := d.ip + "/" + c.TransportProto
					n := got[key]
					n.Packets += d.packets
					n.Bytes += d.bytes
					got[key] = n
				}
			}
			for key, want := range ledger {
				if got[key] != want {
					t.Fatalf("recon both-direction reconciliation %s: %+v != %+v", key, got[key], want)
				}
			}
		})
	}
}

func TestBookVPNAndUnexpectedService(t *testing.T) {
	b, input := newBookCapture(t)
	for _, p := range []layers.IPProtocol{layers.IPProtocolESP, layers.IPProtocolAH, layers.IPProtocolGRE} {
		payload := []byte{0, 0, 0, 1, 0, 0, 0, 2, 0xaa, 0xbb, 0xcc, 0xdd, 0, 0, 0, 0}
		if p == layers.IPProtocolAH {
			payload[0] = 59
			payload[1] = 2
		}
		if p == layers.IPProtocolGRE {
			payload[0] = 0
			payload[1] = 0
			payload[2] = 0x65
			payload[3] = 0x58
		}
		b.network("192.0.2.1", "198.51.100.1", p, payload)
		for range 2 {
			b.network("198.51.100.1", "192.0.2.1", p, append(append([]byte(nil), payload...), bytes.Repeat([]byte{0x42}, 32)...))
		}
	}
	b.udp("192.0.2.1", "198.51.100.1", 4500, 4500, []byte{0, 0, 0, 1, 0, 0, 0, 2, 0xca, 0xfe})
	for range 2 {
		b.udp("198.51.100.1", "192.0.2.1", 4500, 4500, bytes.Repeat([]byte{0x42}, 80))
	}
	b.conversation("192.0.2.2", "198.51.100.2", 55100, 8088, false, bookMessage{false, "GET /nonstandard HTTP/1.1\r\nHost: lab.invalid\r\n\r\n"}, bookMessage{true, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"})
	b.conversation("192.0.2.2", "198.51.100.2", 55101, 80, false, bookMessage{false, "NOT HTTP\x00\xff"}, bookMessage{true, "OPAQUE\x00"})
	ledger := bookWireCounts(t, input)
	for _, workers := range []int{1, 4} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			out := runBookCase(t, input, workers, false)
			r := bookFlow(t, out, `SrcIP == "192.0.2.1" || DstIP == "192.0.2.1"`, "protocol")
			if r.Matched != 4 || len(r.Groups) != 4 {
				t.Fatalf("VPN protocols merged or missing: %+v", r)
			}
			for _, g := range r.Groups {
				if g.Key == "" {
					t.Fatal("missing outer protocol")
				}
				if g.Packets != 3 {
					t.Fatalf("VPN direction lost: %+v", g)
				}
			}
			connections := bookRecords(t, out, "Connection", func() *types.Connection { return new(types.Connection) })
			checked := 0
			for _, c := range connections {
				if c.SrcIP != "192.0.2.1" {
					continue
				}
				checked++
				client, server := ledger[c.SrcIP+"/"+c.TransportProto], ledger[c.DstIP+"/"+c.TransportProto]
				if client.Packets != 1 || server.Packets != 2 || client.Bytes >= server.Bytes || c.PacketsClientToServer != client.Packets || c.BytesClientToServer != client.Bytes || c.PacketsServerToClient != server.Packets || c.BytesServerToClient != server.Bytes || c.TotalSize64 != client.Bytes+server.Bytes {
					t.Fatalf("VPN directional ledger mismatch: %v, client=%+v server=%+v", c, client, server)
				}
			}
			if checked != 4 {
				t.Fatal("not every VPN protocol reconciled")
			}
			http := bookRecords(t, out, "HTTP", func() *types.HTTP { return new(types.HTTP) })
			if len(http) != 1 || http[0].DstPort != 8088 || http[0].URL != "/nonstandard" {
				t.Fatalf("port inferred as application: %v", http)
			}
			r = bookFlow(t, out, `DstPort != "80" && DstPort == "8088"`, "dstPort")
			if r.Matched != 1 {
				t.Fatal("include/exclude service predicate")
			}
			bookStream(t, out, "NOT HTTP\x00\xff", "OPAQUE\x00")
		})
	}
}

func TestBookExternalPrivateLeakAndRetiredHost(t *testing.T) {
	b, input := newBookCapture(t)
	// This fixture's declared vantage is the external side of a lab NAT.
	// The public source is the translated control; RFC1918/ULA sources are
	// policy candidates, not proof of a faulty NAT rule or endpoint ownership.
	for _, src := range []string{"10.1.2.3", "192.0.2.254"} {
		b.udp(src, "198.51.100.1", 56000, 53, []byte("lab"))
	}
	for _, src := range []string{"fd00::20", "2001:db8::20"} {
		b.network(src, "2001:db8:1::1", layers.IPProtocolESP, []byte{0, 0, 0, 1, 0, 0, 0, 1, 0xaa})
	}
	for i := range 3 {
		b.offset = time.Duration(i) * time.Second
		for range 3 {
			b.packet("192.0.2.70", "198.51.100.70", &layers.TCP{SrcPort: layers.TCPPort(56100 + i), DstPort: 524, Seq: 1, SYN: true}, "", false)
		}
	}
	for _, workers := range []int{1, 4} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			out := runBookCase(t, input, workers, false)
			r := bookFlow(t, out, `InSubnet(SrcIP,"10.0.0.0/8") || InSubnet(SrcIP,"fc00::/7")`, "srcIP")
			if r.Matched != 2 {
				t.Fatalf("external private/ULA candidates: %+v", r)
			}
			all := bookFlow(t, out, "true", "dstIP")
			retired := bookFlow(t, out, `DstIP == "198.51.100.70"`, "dstIP")
			if retired.Matched != 3 || len(retired.Groups[0].Members) != 3 {
				t.Fatal("retired-address evidence")
			}
			failed := bookFlow(t, out, `DstIP == "198.51.100.70" && NumSYNFlags == 3 && NumACKFlags == 0`, "dstIP")
			if failed.Matched != 3 {
				t.Fatal("retired address unexpectedly answered")
			}
			found := false
			for _, g := range all.Groups {
				if g.Key == "198.51.100.70" {
					found = true
					if g.BytePercent <= 0 || g.BytePercent >= 100 || g.Bytes != retired.Groups[0].Bytes {
						t.Fatalf("site bandwidth share: %+v", g)
					}
				}
			}
			if !found {
				t.Fatal("retired host not ranked")
			}
			r, err := flow.ReadFile(context.Background(), filepath.Join(out, "Connection.ncap"), flow.Query{StartNs: 1700000000000000000, EndNs: 1700000003000000000, Expression: `DstIP == "198.51.100.70"`, GroupBy: "dstIP", SortBy: "bytes", Limit: 10, BucketNs: int64(time.Second)})
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Series) != 3 {
				t.Fatal("site traffic series")
			}
			for _, bin := range r.Series {
				if bin.EstimatedBytes <= 0 {
					t.Fatal("recurring retired-address attempt missing")
				}
			}
		})
	}
}

func bookWords(values ...uint32) []byte {
	b := make([]byte, len(values)*4)
	for i, v := range values {
		binary.BigEndian.PutUint32(b[i*4:], v)
	}
	return b
}
func bookShorts(values ...uint16) []byte {
	b := make([]byte, len(values)*2)
	for i, v := range values {
		binary.BigEndian.PutUint16(b[i*2:], v)
	}
	return b
}

func TestBookFlowExportCoverage(t *testing.T) {
	b, input := newBookCapture(t)
	set := func(id uint16, body []byte) []byte { return append(bookShorts(id, uint16(len(body)+4)), body...) }
	for _, version := range []uint16{9, 10} {
		src := fmt.Sprintf("192.0.2.%d", version)
		packet := func(seq uint32, s []byte) []byte {
			if version == 9 {
				return append(append(bookShorts(9, 1), bookWords(120000, 1700000000, seq, 7)...), s...)
			}
			return append(append(bookShorts(10, uint16(16+len(s))), bookWords(1700000000, seq, 7)...), s...)
		}
		start, end := uint16(22), uint16(21)
		templateSet := uint16(0)
		if version == 10 {
			start, end, templateSet = 150, 151, 2
		}
		template := bookShorts(256, 9, 8, 4, 12, 4, 1, 4, 2, 4, start, 4, end, 4, 34, 4, 36, 4, 37, 4)
		b.udp(src, "192.0.2.253", 50000, 2055, packet(0, set(templateSet, template)))
		for i := range 2 {
			first, last := uint32(i*60000), uint32((i+1)*60000)
			if version == 10 {
				first, last = 1699999880+uint32(i*60), 1699999940+uint32(i*60)
			}
			var records []byte
			for _, pair := range [][2]uint32{{0xc0000201, 0xc6336401}, {0xc6336401, 0xc0000201}} {
				records = append(records, bookWords(pair[0], pair[1], 1000, 10, first, last, 100, 60, 15)...)
			}
			seq := uint32(i + 1)
			if version == 10 {
				seq = uint32(i * 2)
			}
			b.udp(src, "192.0.2.253", 50000, 2055, packet(seq, set(256, records)))
		}
		// Unknown template must be reported, never interpreted as zero traffic.
		b.udp(src, "192.0.2.253", 50000, 2055, packet(20, set(333, bookWords(0))))
	}
	ip := bookWords(1500, 6, 0xc0000201, 0xc6336401, 12345, 443, 0x12, 0)
	record := append(bookWords(3, uint32(len(ip))), ip...)
	sample := append(bookWords(1, 1, 1000, 1000, 0, 2, 3, 1), record...)
	sflow := append(bookWords(5, 1, 0xc000020b, 1, 1, 120000, 1, 1, uint32(len(sample))), sample...)
	b.udp("192.0.2.11", "192.0.2.253", 6343, 6343, sflow)
	for _, workers := range []int{1, 2, 4, 8} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			out := runBookCase(t, input, workers, false)
			path := filepath.Join(out, "FlowExports.jsonl")
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			scanner := bufio.NewScanner(f)
			observations := 0
			missing, loss := 0, 0
			for scanner.Scan() {
				var e flowexport.Event
				if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
					t.Fatal(err)
				}
				if e.Kind == "observation" {
					o := e.Observation
					observations++
					if o.Envelope.PacketOrdinal == 0 || o.ID == "" {
						t.Fatalf("missing export provenance: %+v", o)
					}
					if o.Format != "sflow-v5" {
						if o.ActiveTimeout == nil || *o.ActiveTimeout != 60 || o.IdleTimeout == nil || *o.IdleTimeout != 15 || o.Sampling.Interval != 100 {
							t.Fatalf("timeout/sampling metadata: %+v", o)
						}
					}
				} else if e.Kind == "issue" {
					if e.Issue.Code == "missing-template" {
						missing++
					}
					if e.Issue.Code == "sequence-discontinuity" {
						loss++
					}
				}
			}
			if err := scanner.Err(); err != nil {
				t.Fatal(err)
			}
			if observations != 9 || missing != 2 || loss == 0 {
				t.Fatalf("records/missing/loss=%d/%d/%d", observations, missing, loss)
			}
			for _, tc := range []struct {
				format, exporter string
				domain           uint32
				bytes            uint64
				records          int
			}{{"netflow-v9", "192.0.2.9:50000", 7, 4000, 4}, {"ipfix", "192.0.2.10:50000", 7, 4000, 4}, {"sflow-v5", "192.0.2.11:6343", 1, 1500, 1}} {
				q := flowexport.Query{StartNs: 1699999800000000000, EndNs: 1700000010000000000, TimeBasis: "receive", Exporter: tc.exporter, Format: tc.format, Domain: &tc.domain, GroupBy: "protocol", Limit: 10}
				r, err := flowexport.ReadReport(context.Background(), path, q)
				if err != nil {
					t.Fatal(err)
				}
				if r.Matched != tc.records || len(r.Groups) != 1 || r.Groups[0].Bytes != tc.bytes || r.Health.Status != "partial" {
					t.Fatalf("raw sampled/split counters or health: %+v", r)
				}
			}
		})
	}
}
