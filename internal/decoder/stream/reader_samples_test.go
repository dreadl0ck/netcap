package stream

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/dreadl0ck/netcap/internal/decoder/stream/quic"
)

// A Hello identifies TLS, but only a Certificate message makes its certificate
// reader emit a record. Generate a small, parseable certificate for that path.
func certificateHandshake(t *testing.T) []byte {
	t.Helper()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"fixture.example"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(4_102_444_800, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert := append([]byte{byte(len(der) >> 16), byte(len(der) >> 8), byte(len(der))}, der...)
	body := append([]byte{byte(len(cert) >> 16), byte(len(cert) >> 8), byte(len(cert))}, cert...)
	handshake := append([]byte{11, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return tlsRecord(22, handshake)
}

// The short Initial header in samples_test.go detects QUIC but cannot produce
// a ClientHello audit record. This tracked capture contains a full exchange.
func capturedQUICClientHello(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join("quic", "testdata", "wireshark-quic-with-secrets.pcapng")
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatal(err)
	}
	packets := gopacket.NewPacketSource(r, r.LinkType())
	for packet := range packets.Packets() {
		udp, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if !ok {
			continue
		}
		hello, err := quic.ParseIETFQUICInitial(udp.Payload)
		if err == nil && hello != nil && (hello.SNI != "" || len(hello.CipherSuites) > 0) {
			return append([]byte(nil), udp.Payload...)
		}
	}
	t.Fatal(fmt.Sprintf("%s contains no decodable QUIC ClientHello", path))
	return nil
}
