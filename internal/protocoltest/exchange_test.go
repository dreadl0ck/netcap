package protocoltest

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type singleByteReader struct{ io.Reader }

func (r singleByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.Reader.Read(p)
}

func TestTLSExchangeVerifiesPeerAndRecordsNegotiation(t *testing.T) {
	fixture := httptest.NewTLSServer(nil)
	certificate := fixture.TLS.Certificates[0]
	fixture.Close()
	caPath := filepath.Join(t.TempDir(), "fixture-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 3 {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			_, _ = conn.Write([]byte("OK\n"))
			_ = conn.Close()
		}
	}()
	exchange := Exchange{Version: 1, Network: "tcp", Address: listener.Addr().String(), TLS: true, RootCAFile: caPath, Framing: Framing{Kind: "delimiter", Delimiter: []byte("\n"), MaxBytes: 32}, TimeoutMilliseconds: 2000, MaxTotalBytes: 64, Steps: []Step{{Receive: true, Expect: []byte("OK\n")}}}
	result, err := Run(context.Background(), exchange)
	if err != nil {
		t.Fatal(err)
	}
	if result.TLSVersion < tls.VersionTLS12 || result.TLSCipher == 0 || result.Status != "matched" {
		t.Fatalf("missing TLS evidence: %+v", result)
	}
	exchange.ServerName = "wrong.invalid"
	result, err = Run(context.Background(), exchange)
	if err == nil || result.Status != "error" {
		t.Fatal("hostname mismatch accepted")
	}
	exchange.ServerName = ""
	exchange.RootCAFile = ""
	result, err = Run(context.Background(), exchange)
	if err == nil || result.Status != "error" {
		t.Fatal("untrusted fixture certificate accepted")
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("TLS fixture did not terminate")
	}
}

func TestUDPExchangePreservesDatagram(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	done := make(chan error, 1)
	go func() {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buffer := make([]byte, 64)
		n, peer, err := conn.ReadFromUDP(buffer)
		if err == nil {
			_, err = conn.WriteToUDP(buffer[:n], peer)
		}
		done <- err
	}()
	payload := []byte{0, 1, 2, 255}
	result, err := Run(context.Background(), Exchange{Version: 1, Network: "udp", Address: conn.LocalAddr().String(), Framing: Framing{MaxBytes: 64}, TimeoutMilliseconds: 2000, MaxTotalBytes: 128, Steps: []Step{{Send: payload, Receive: true, Expect: payload}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(result.Observations) != 2 || !bytes.Equal(result.Observations[1].Bytes, payload) {
		t.Fatal("UDP exchange altered datagram")
	}
}

func FuzzFraming(f *testing.F) {
	f.Add([]byte{0, 3, 'o', 'n', 'e'})
	f.Fuzz(func(t *testing.T, data []byte) {
		framing := Framing{Kind: "length-prefix", LengthBytes: 2, ByteOrder: "big", MaxBytes: 1024}
		frames, err := framing.ParseAll(data)
		if err == nil && !bytes.Equal(bytes.Join(frames, nil), data) {
			t.Fatal("successful parse silently discarded bytes")
		}
	})
}

func TestFramingFragmentationCoalescingAndTrailingBytes(t *testing.T) {
	f := Framing{Kind: "length-prefix", LengthBytes: 2, ByteOrder: "big", MaxBytes: 64}
	data := []byte{0, 3, 'o', 'n', 'e', 0, 3, 't', 'w', 'o'}
	r := singleByteReader{bytes.NewReader(data)}
	for _, want := range [][]byte{data[:5], data[5:]} {
		got, err := f.Read(r)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("framing: %x %v", got, err)
		}
	}
	frames, err := f.ParseAll(data)
	if err != nil || len(frames) != 2 {
		t.Fatalf("coalesced: %v %v", frames, err)
	}
	for _, bad := range [][]byte{{0}, {0, 3, 'x'}, {255, 255}, append(append([]byte(nil), data...), 0)} {
		if _, err := f.ParseAll(bad); err == nil {
			t.Fatalf("accepted partial/oversized %x", bad)
		}
	}
	f = Framing{Kind: "fixed", FixedSize: 4, MaxBytes: 4}
	got, err := f.Read(bytes.NewReader([]byte{1, 2}))
	if err == nil || !bytes.Equal(got, []byte{1, 2}) {
		t.Fatal("incomplete evidence padded with fabricated bytes")
	}
}

func TestStatefulExchangeCapturesFreshResponse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			server <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write([]byte("fresh-123\n")); err != nil {
			server <- err
			return
		}
		got := make([]byte, len("AUTH fresh-123\n"))
		_, err = io.ReadFull(conn, got)
		if err == nil && !bytes.Equal(got, []byte("AUTH fresh-123\n")) {
			err = io.ErrUnexpectedEOF
		}
		if err == nil {
			_, err = conn.Write([]byte("OK\n"))
		}
		server <- err
	}()
	exchange := Exchange{Version: 1, Network: "tcp", Address: listener.Addr().String(), Framing: Framing{Kind: "delimiter", Delimiter: []byte("\n"), MaxBytes: 64}, TimeoutMilliseconds: 2000, MaxTotalBytes: 256, Steps: []Step{
		{Name: "challenge", Receive: true, CaptureVariable: "challenge", CaptureLength: 10},
		{Name: "reply", Send: []byte("AUTH "), SendVariable: "challenge", Receive: true, Expect: []byte("OK\n")},
	}}
	result, err := Run(context.Background(), exchange)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-server; err != nil {
		t.Fatal(err)
	}
	if result.Status != "matched" || len(result.Observations) != 3 || string(result.Observations[1].Bytes) != "AUTH fresh-123\n" || len(result.ConfigurationSHA256) != 64 {
		t.Fatalf("exchange evidence: %+v", result)
	}
}

func TestExchangeTimeoutKeepsPartialBytes(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte{0, 4, 'x'})
		var b [1]byte
		_, _ = conn.Read(b[:])
	}()
	result, err := Run(context.Background(), Exchange{Version: 1, Network: "tcp", Address: listener.Addr().String(), Framing: Framing{Kind: "length-prefix", LengthBytes: 2, ByteOrder: "big", MaxBytes: 64}, TimeoutMilliseconds: 100, MaxTotalBytes: 128, Steps: []Step{{Receive: true}}})
	if err == nil || result.Status != "error" || len(result.Observations) != 1 || !bytes.Equal(result.Observations[0].Bytes, []byte{0, 4, 'x'}) {
		t.Fatalf("timeout falsely succeeded or lost bytes: %+v %v", result, err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("connection not closed")
	}
}
