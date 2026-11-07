package webui

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func observedTuplePCAP(t *testing.T) (string, time.Time) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "owned.pcap")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := pcapgo.NewWriterNanos(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1700000000, 0)
	for index, candidate := range []struct {
		src, dst string
		sp, dp   uint16
		udp      bool
	}{
		{"192.0.2.1", "198.51.100.1", 52123, 9243, false},
		{"192.0.2.1", "198.51.100.1", 52123, 9243, false},
		{"198.51.100.1", "192.0.2.1", 9243, 52123, false},
		{"192.0.2.1", "198.51.100.1", 52124, 9243, false},
		{"192.0.2.1", "198.51.100.1", 9243, 52123, false},
		{"192.0.2.1", "198.51.100.1", 52123, 9243, true},
	} {
		eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.ParseIP(candidate.src), DstIP: net.ParseIP(candidate.dst), Protocol: layers.IPProtocolTCP}
		var transport gopacket.SerializableLayer
		if candidate.udp {
			ip.Protocol = layers.IPProtocolUDP
			udp := &layers.UDP{SrcPort: layers.UDPPort(candidate.sp), DstPort: layers.UDPPort(candidate.dp)}
			if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
				t.Fatal(err)
			}
			transport = udp
		} else {
			tcp := &layers.TCP{SrcPort: layers.TCPPort(candidate.sp), DstPort: layers.TCPPort(candidate.dp), SYN: true}
			if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
				t.Fatal(err)
			}
			transport = tcp
		}
		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, transport); err != nil {
			t.Fatal(err)
		}
		if err := writer.WritePacket(gopacket.CaptureInfo{Timestamp: base.Add(time.Duration(min(index, 2))), CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes())}, buf.Bytes()); err != nil {
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path, base
}

func TestHTTPPacketExportUsesObservedTupleTransportAndTime(t *testing.T) {
	path, base := observedTuplePCAP(t)
	s := &Server{activeInputFile: path}
	query := url.Values{"srcIP": {"192.0.2.1"}, "dstIP": {"198.51.100.1"}, "srcPort": {"52123"}, "dstPort": {"9243"}, "startNs": {"1700000000000000001"}, "endNs": {"1700000000000000002"}}
	for name, handler := range map[string]http.HandlerFunc{"HTTP": s.handleHTTPDownloadPCAP, "certificate": s.handleCertificateDownloadPCAP} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler(response, httptest.NewRequest("GET", "/download-pcap?"+query.Encode(), nil))
			if response.Code != 200 {
				t.Fatalf("%d: %s", response.Code, response.Body.String())
			}
			reader, err := pcapgo.NewReader(bytes.NewReader(response.Body.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for {
				_, info, err := reader.ReadPacketData()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				count++
				if !info.Timestamp.Equal(base.Add(time.Duration(count))) {
					t.Fatalf("wrong capture time: %v", info.Timestamp)
				}
			}
			if count != 2 {
				t.Fatalf("matched %d packets, want request and reverse response only", count)
			}
			for field, value := range map[string]string{"srcPort": "", "srcIP": "192.0.2.1 or host 203.0.113.1", "protocol": "UDP", "endNs": "invalid"} {
				invalid, _ := url.ParseQuery(query.Encode())
				invalid.Set(field, value)
				response := httptest.NewRecorder()
				handler(response, httptest.NewRequest("GET", "/download-pcap?"+invalid.Encode(), nil))
				if response.Code != 400 {
					t.Fatalf("accepted %s=%q: %d", field, value, response.Code)
				}
			}
		})
	}
}
