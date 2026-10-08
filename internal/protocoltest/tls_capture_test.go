package protocoltest

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

type tlsWireChunk struct {
	outbound bool
	data     []byte
}
type tlsRecordingConn struct {
	net.Conn
	mu     sync.Mutex
	chunks []tlsWireChunk
}

func (c *tlsRecordingConn) Read(data []byte) (int, error) {
	n, err := c.Conn.Read(data)
	if n > 0 {
		c.mu.Lock()
		c.chunks = append(c.chunks, tlsWireChunk{false, append([]byte(nil), data[:n]...)})
		c.mu.Unlock()
	}
	return n, err
}
func (c *tlsRecordingConn) Write(data []byte) (int, error) {
	n, err := c.Conn.Write(data)
	if n > 0 {
		c.mu.Lock()
		c.chunks = append(c.chunks, tlsWireChunk{true, append([]byte(nil), data[:n]...)})
		c.mu.Unlock()
	}
	return n, err
}

func TestTLSCaptureAdapterDecryptsKnownSecrets(t *testing.T) {
	if _, err := exec.LookPath("tshark"); err != nil {
		if os.Getenv("NETCAP_REQUIRE_TLS_ADAPTER") == "1" {
			t.Fatal(err)
		}
		t.Skip("tshark adapter is not installed")
	}
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "fixture-decrypted-response") }))
			server.TLS = &tls.Config{MinVersion: version, MaxVersion: version}
			server.StartTLS()
			defer server.Close()
			raw, err := net.Dial("tcp", server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			recorder := &tlsRecordingConn{Conn: raw}
			defer recorder.Close()
			var keyLog bytes.Buffer
			config := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			config.MinVersion, config.MaxVersion = version, version
			config.ServerName = "127.0.0.1"
			config.KeyLogWriter = &keyLog
			client := tls.Client(recorder, config)
			if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := client.Write([]byte("GET /fixture HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n")); err != nil {
				t.Fatal(err)
			}
			response, err := io.ReadAll(client)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(response, []byte("fixture-decrypted-response")) {
				t.Fatal("TLS fixture response missing")
			}
			_ = client.Close()
			dir := t.TempDir()
			capture, keys := filepath.Join(dir, "tls.pcap"), filepath.Join(dir, "secrets.log")
			if err := os.WriteFile(keys, keyLog.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			file, err := os.Create(capture)
			if err != nil {
				t.Fatal(err)
			}
			writer := pcapgo.NewWriterNanos(file)
			if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
				t.Fatal(err)
			}
			seq := [2]uint32{100, 200}
			index := 0
			emit := func(direction int, data []byte, syn, ack bool) {
				t.Helper()
				other := 1 - direction
				ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: []net.IP{net.IPv4(192, 0, 2, 1), net.IPv4(192, 0, 2, 2)}[direction], DstIP: []net.IP{net.IPv4(192, 0, 2, 1), net.IPv4(192, 0, 2, 2)}[other]}
				tcp := &layers.TCP{SrcPort: []layers.TCPPort{12345, 443}[direction], DstPort: []layers.TCPPort{12345, 443}[other], Seq: seq[direction], Ack: seq[other], SYN: syn, ACK: ack, PSH: len(data) > 0, Window: 65535}
				if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
					t.Fatal(err)
				}
				buffer := gopacket.NewSerializeBuffer()
				eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, byte(direction + 1)}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, byte(other + 1)}, EthernetType: layers.EthernetTypeIPv4}
				if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload(data)); err != nil {
					t.Fatal(err)
				}
				packet := buffer.Bytes()
				if err := writer.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1700000000, int64(index)*1000000), CaptureLength: len(packet), Length: len(packet)}, packet); err != nil {
					t.Fatal(err)
				}
				index++
				seq[direction] += uint32(len(data))
				if syn {
					seq[direction]++
				}
			}
			emit(0, nil, true, false)
			emit(1, nil, true, true)
			emit(0, nil, false, true)
			for _, chunk := range recorder.chunks {
				direction := 1
				if chunk.outbound {
					direction = 0
				}
				for len(chunk.data) > 0 {
					n := min(len(chunk.data), 1400)
					emit(direction, chunk.data[:n], false, true)
					chunk.data = chunk.data[n:]
				}
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			result, err := AnalyzeTLSCapture(ctx, capture, keys, 0)
			if err != nil {
				t.Fatal(err)
			}
			plaintext := append(append([]byte(nil), result.Client...), result.Server...)
			if !bytes.Contains(plaintext, []byte("GET /fixture")) || !bytes.Contains(plaintext, []byte("fixture-decrypted-response")) {
				t.Fatalf("plaintext mismatch: %q %q", result.Client, result.Server)
			}
			bad := []byte(strings.ReplaceAll(keyLog.String(), " ", " 00"))
			if err := os.WriteFile(keys, bad, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := AnalyzeTLSCapture(ctx, capture, keys, 0); err == nil {
				t.Fatal("invalid secrets reported successful plaintext")
			}
		})
	}
}
