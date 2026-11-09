package collector

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

type dsbChunk struct {
	side int
	data []byte
}
type dsbRecordingConn struct {
	net.Conn
	mu     sync.Mutex
	chunks []dsbChunk
}

func (c *dsbRecordingConn) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	c.mu.Lock()
	c.chunks = append(c.chunks, dsbChunk{1, bytes.Clone(b[:n])})
	c.mu.Unlock()
	return n, e
}
func (c *dsbRecordingConn) Write(b []byte) (int, error) {
	n, e := c.Conn.Write(b)
	c.mu.Lock()
	c.chunks = append(c.chunks, dsbChunk{0, bytes.Clone(b[:n])})
	c.mu.Unlock()
	return n, e
}

func TestPCAPNGEmbeddedTLSKeys(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "DSB end-to-end fixture") }))
			server.TLS = &tls.Config{MinVersion: version, MaxVersion: version}
			server.StartTLS()
			defer server.Close()
			raw, err := net.Dial("tcp", server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			recorder := &dsbRecordingConn{Conn: raw}
			defer recorder.Close()
			var keys bytes.Buffer
			cfg := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			cfg.ServerName = "127.0.0.1"
			cfg.MinVersion, cfg.MaxVersion, cfg.KeyLogWriter = version, version, &keys
			client := tls.Client(recorder, cfg)
			_ = client.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := client.Write([]byte("GET /fixture HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n")); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadAll(client); err != nil {
				t.Fatal(err)
			}
			_ = client.Close()
			path := filepath.Join(t.TempDir(), "embedded.pcapng")
			f, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			writer, err := pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)
			if err != nil {
				t.Fatal(err)
			}
			seq := [2]uint32{100, 200}
			index := 0
			emit := func(side int, data []byte, syn, ack bool) {
				other := 1 - side
				addresses := []net.IP{net.IPv4(192, 0, 2, 1), net.IPv4(198, 51, 100, 1)}
				ports := []layers.TCPPort{12345, 443}
				ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: addresses[side], DstIP: addresses[other]}
				tcp := &layers.TCP{SrcPort: ports[side], DstPort: ports[other], Seq: seq[side], Ack: seq[other], SYN: syn, ACK: ack, PSH: len(data) > 0, Window: 65535}
				_ = tcp.SetNetworkLayerForChecksum(ip)
				eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, byte(side + 1)}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, byte(other + 1)}, EthernetType: layers.EthernetTypeIPv4}
				b := gopacket.NewSerializeBuffer()
				if err := gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload(data)); err != nil {
					t.Fatal(err)
				}
				frame := b.Bytes()
				if err := writer.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1700000000, int64(index)*1e6), CaptureLength: len(frame), Length: len(frame)}, frame); err != nil {
					t.Fatal(err)
				}
				index++
				seq[side] += uint32(len(data))
				if syn {
					seq[side]++
				}
			}
			emit(0, nil, true, false)
			emit(1, nil, true, true)
			emit(0, nil, false, true)
			for _, chunk := range recorder.chunks {
				for len(chunk.data) > 0 {
					n := min(len(chunk.data), 1400)
					emit(chunk.side, chunk.data[:n], false, true)
					chunk.data = chunk.data[n:]
				}
			}
			if err := writer.Flush(); err != nil {
				t.Fatal(err)
			}
			// A late DSB must be admitted by the count pass before any stream retires.
			body := binary.LittleEndian.AppendUint32(nil, 0x544c534b)
			body = binary.LittleEndian.AppendUint32(body, uint32(keys.Len()))
			body = append(body, keys.Bytes()...)
			for len(body)%4 != 0 {
				body = append(body, 0)
			}
			block := binary.LittleEndian.AppendUint32(nil, 10)
			block = binary.LittleEndian.AppendUint32(block, uint32(len(body)+12))
			block = append(block, body...)
			block = binary.LittleEndian.AppendUint32(block, uint32(len(body)+12))
			if _, err := f.Write(block); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(t.TempDir(), "audit")
			ultimateRun(t, path, out, 4, 0)
			records := bookRecords(t, out, "HTTP", func() *types.HTTP { return &types.HTTP{} })
			if len(records) != 1 || records[0].URL != "/fixture" || records[0].StatusCode != 200 || !slices.Contains(records[0].ParseQualifications, "decrypted-tls-key-log") {
				t.Fatalf("embedded TLS HTTP evidence missing: %+v", records)
			}
		})
	}
}
