package tls

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

func ownedCertificate(t *testing.T, otherSigner bool, until time.Time) ([]byte, *x509.Certificate) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	signer := key
	template := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "owned.example.test"}, NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: until, DNSNames: []string{"owned.example.test"}, KeyUsage: x509.KeyUsageDigitalSignature}
	parent := *template
	if otherSigner {
		signer = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32))
	}
	parent.PublicKey = signer.Public()
	der, err := x509.CreateCertificate(rand.Reader, template, &parent, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return der, cert
}

func TestCertificateCaptureTimeAndSelfSignature(t *testing.T) {
	_, cert := ownedCertificate(t, false, time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC))
	for _, tc := range []struct {
		at       int64
		validity string
	}{{0, "unavailable"}, {time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano(), "not-yet-valid"}, {time.Date(2020, 6, 1, 0, 0, 0, 0, time.UTC).UnixNano(), "valid"}, {time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano(), "expired"}} {
		a := assessCertificate(cert, tc.at)
		if a.validity != tc.validity || a.selfSignature != "verified" || !a.selfSigned {
			t.Fatalf("assessment: %+v", a)
		}
		if tc.at == 0 && a.basis != "unavailable" {
			t.Fatal("wall time invented")
		}
	}
	_, external := ownedCertificate(t, true, cert.NotAfter)
	if a := assessCertificate(external, cert.NotBefore.UnixNano()); a.selfSigned || a.selfSignature != "invalid" {
		t.Fatalf("same issuer DN misclassified: %+v", a)
	}
	unsupported := *cert
	unsupported.SignatureAlgorithm = x509.UnknownSignatureAlgorithm
	if a := assessCertificate(&unsupported, cert.NotBefore.UnixNano()); a.selfSignature != "unsupported" {
		t.Fatal("unsupported signature reported clean", a)
	}
	_, far := ownedCertificate(t, false, time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC))
	if certificateUnixNano(far.NotAfter) != 0 || assessCertificate(far, cert.NotBefore.UnixNano()).days < 2_000_000 {
		t.Fatal("out-of-range certificate date overflowed")
	}
	boundary := *cert
	boundary.NotAfter = cert.NotBefore.Add(24 * time.Hour)
	if a := assessCertificate(&boundary, cert.NotBefore.Add(time.Nanosecond).UnixNano()); a.days != 0 {
		t.Fatal("expiration days rounded across capture nanoseconds", a.days)
	}
}

type semanticsCertificateWriter struct {
	netio.AuditRecordWriter
	records []*types.TLSCertificate
}

func (w *semanticsCertificateWriter) Write(m proto.Message) error {
	w.records = append(w.records, proto.Clone(m).(*types.TLSCertificate))
	return nil
}

func TestCertificateMutualTLSSenderAndFraming(t *testing.T) {
	oldConfig := decoderconfig.Instance
	decoderconfig.Instance = &decoderconfig.Config{Quiet: true, StreamBufferSize: 8, NumStreamWorkers: 1}
	defer func() { decoderconfig.Instance = oldConfig }()
	der, _ := ownedCertificate(t, false, time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC))
	list := append([]byte{byte(len(der) >> 16), byte(len(der) >> 8), byte(len(der))}, der...)
	message := append([]byte{byte(len(list) >> 16), byte(len(list) >> 8), byte(len(list))}, list...)
	handshake := append([]byte{11, byte(len(message) >> 16), byte(len(message) >> 8), byte(len(message))}, message...)
	wire := recordWire(22, handshake)
	old, oldCount := Decoder.Writer, Decoder.NumRecordsWritten
	defer func() { Decoder.Writer = old; Decoder.NumRecordsWritten = oldCount; ResetCertificates() }()
	const ts = int64(1590969600000000123)
	for _, split := range []int{0, 1, 4, 5, 7, len(wire) / 2, len(wire)} {
		ResetCertificates()
		w := &semanticsCertificateWriter{}
		Decoder.Writer = w
		h := &tlsReader{conversation: &core.ConversationInfo{ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", ClientPort: 1234, ServerPort: 443, CommunityID: "1:owned"}}
		for _, dir := range []reassembly.TCPFlowDirection{reassembly.TCPDirClientToServer, reassembly.TCPDirServerToClient} {
			f := &tlsRecordFramer{reader: h, dir: dir, emit: func(*types.TLSRecord) {}}
			f.feed(wire[:split], ts)
			f.feed(wire[split:], ts)
			f.eof()
		}
		flushCertificates(Decoder)
		if len(w.records) != 2 {
			t.Fatalf("split %d: same certificate lost a sender: %d", split, len(w.records))
		}
		peers := map[string]string{}
		for _, r := range w.records {
			peers[r.CertificateSender] = r.SrcIP
			if r.Timestamp != ts || r.AssessmentTime != ts || r.AssessmentBasis != "capture-time" || r.ValidityState != "valid" || !r.IsSelfSigned || r.CommunityID != "1:owned" {
				t.Fatalf("split%d: %+v", split, r)
			}
		}
		if peers["client"] != "192.0.2.1" || peers["server"] != "192.0.2.2" {
			t.Fatal("mutual TLS attributed to wrong peer", peers)
		}
	}
}

func FuzzCertificateHandshakeSemantics(f *testing.F) {
	f.Add([]byte{0, 0, 0})
	f.Add([]byte{0, 0, 3, 0, 0, 0})
	f.Add([]byte{255, 255, 255})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		ResetCertificates()
		defer ResetCertificates()
		h := &tlsReader{conversation: &core.ConversationInfo{}}
		h.parseCertificateMessage(b, 1, reassembly.TCPDirServerToClient)
	})
}
