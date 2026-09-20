package ja4

import "testing"

func TestJA4SpecificationExample(t *testing.T) {
	fingerprint := ComputeJA4(&ClientHelloData{
		Version:       0x0303,
		SupportedVers: 0x0304,
		CipherSuites: []uint16{
			0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9,
			0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
		},
		Extensions: []uint16{
			0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d,
			0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
		},
		SNI:   "example.com",
		ALPNs: []string{"h2"},
		SignatureAlgorithms: []uint16{
			0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
		},
	})

	const expected = "t13d1516h2_8daaf6152771_e5627efa2ab1"
	if fingerprint != expected {
		t.Fatalf("ComputeJA4() = %q, want %q", fingerprint, expected)
	}
	if !ValidateJA4(fingerprint) {
		t.Fatalf("ComputeJA4() produced invalid fingerprint %q", fingerprint)
	}
}

func TestJA4QUICTransport(t *testing.T) {
	fingerprint := ComputeJA4(&ClientHelloData{
		Version:       0x0303,
		SupportedVers: 0x0304,
		CipherSuites:  []uint16{0x1301},
		Extensions:    []uint16{0x0000, 0x0010},
		SNI:           "192.0.2.1",
		ALPNs:         []string{"h3"},
		IsQUIC:        true,
	})
	if fingerprint[0] != 'q' {
		t.Fatalf("ComputeJA4() = %q, want QUIC prefix", fingerprint)
	}
}
