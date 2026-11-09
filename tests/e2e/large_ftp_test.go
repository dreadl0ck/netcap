//go:build e2e

package e2e

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestLargeFTPExtractionCLI(t *testing.T) {
	if testing.Short() {
		t.Skip("28 MB FTP replay")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	temp := t.TempDir()
	binary := filepath.Join(temp, "net")
	build := exec.Command("go", "build", "-tags=nodpi,noyara,nomagika", "-o", binary, "./cmd/net")
	build.Dir, build.Env = root, append(os.Environ(), "GOWORK=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, output)
	}
	body := make([]byte, 27_888_036)
	for i := range body {
		body[i] = byte(i * 31)
	}
	want := fmt.Sprintf("%x", sha256.Sum256(body))
	capture := filepath.Join(temp, "large-ftp.pcap")
	writeLargeFTP(t, capture, body)
	for _, workers := range []int{1, 4} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "audit")
			cmd := exec.Command(binary, "capture", "--read", capture, "--out", out, "--workers", fmt.Sprint(workers), "--include", "FTP,File", "--compress=false", "--dpi=false", "--geoDB=false", "--network-detection=false", "--fileStorage", "files", "--http", "", "--quiet", "-y")
			cmd.Env = append(os.Environ(), "NC_CONFIG_ROOT="+filepath.Join(temp, "config"))
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("capture: %v %s", err, output)
			}
			found := false
			for _, record := range readSemanticRecords(t, out, "File") {
				file := record.(*types.File)
				if file.Protocol != "FTP" {
					continue
				}
				if file.Length != int64(len(body)) || file.Hashes.GetSHA256() != want {
					t.Fatalf("FTP truncated: size=%d sha256=%s", file.Length, file.Hashes.GetSHA256())
				}
				stored, err := os.ReadFile(file.Location)
				if err != nil || fmt.Sprintf("%x", sha256.Sum256(stored)) != want {
					t.Fatalf("stored FTP bytes mismatch: %v", err)
				}
				found = true
			}
			if !found {
				t.Fatal("FTP data transfer was not associated/extracted")
			}
		})
	}
}

func writeLargeFTP(t *testing.T, path string, body []byte) {
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
	flow := func(clientPort, serverPort layers.TCPPort) func(bool, string, []byte) {
		clientSeq, serverSeq := uint32(100), uint32(500)
		return func(server bool, flags string, data []byte) {
			ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(198, 51, 100, 1)}
			tcp := &layers.TCP{SrcPort: clientPort, DstPort: serverPort, Seq: clientSeq, Ack: serverSeq, ACK: true, Window: 65535}
			if server {
				ip.SrcIP, ip.DstIP = ip.DstIP, ip.SrcIP
				tcp.SrcPort, tcp.DstPort, tcp.Seq, tcp.Ack = serverPort, clientPort, serverSeq, clientSeq
			}
			tcp.SYN, tcp.FIN, tcp.PSH = flags == "syn" || flags == "synack", flags == "fin", len(data) > 0
			if flags == "syn" {
				tcp.ACK, tcp.Ack = false, 0
			}
			if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
				t.Fatal(err)
			}
			eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
			b := gopacket.NewSerializeBuffer()
			if err := gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload(data)); err != nil {
				t.Fatal(err)
			}
			raw := b.Bytes()
			if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1700000000, int64(ordinal)*1_000_000), CaptureLength: len(raw), Length: len(raw)}, raw); err != nil {
				t.Fatal(err)
			}
			ordinal++
			increment := uint32(len(data))
			if tcp.SYN || tcp.FIN {
				increment++
			}
			if server {
				serverSeq += increment
			} else {
				clientSeq += increment
			}
		}
	}
	control := flow(12345, 21)
	control(false, "syn", nil)
	control(true, "synack", nil)
	control(false, "ack", nil)
	for _, exchange := range []struct{ client, server string }{
		{"", "220 Fixture FTP ready\r\n"},
		{"USER fixture\r\n", "331 Password required\r\n"},
		{"PASS fixture\r\n", "230 Login successful\r\n"},
		{"TYPE I\r\n", "200 Binary mode\r\n"},
		{"PASV\r\n", "227 Entering Passive Mode (198,51,100,1,195,80)\r\n"},
		{"RETR large.bin\r\n", "150 Opening binary data connection\r\n"},
	} {
		if exchange.client != "" {
			control(false, "ack", []byte(exchange.client))
		}
		control(true, "ack", []byte(exchange.server))
	}
	data := flow(12346, 50000)
	data(false, "syn", nil)
	data(true, "synack", nil)
	data(false, "ack", nil)
	for len(body) > 0 {
		n := min(1460, len(body))
		data(true, "ack", body[:n])
		data(false, "ack", nil)
		body = body[n:]
	}
	data(true, "fin", nil)
	data(false, "fin", nil)
	data(true, "ack", nil)
	control(true, "ack", []byte("226 Transfer complete\r\n"))
	control(false, "ack", []byte("QUIT\r\n"))
	control(true, "ack", []byte("221 Goodbye\r\n"))
	control(true, "fin", nil)
	control(false, "fin", nil)
	control(true, "ack", nil)
}
