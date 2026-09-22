package protobuf

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// This file pins the detection tightening of 2026-09-22. Byte statistics alone
// are a weak signature: IsProtobufData tested only for a high-bit byte, a spread
// of b&0x07 values and entropy above 3.0, none of which inspects the wire
// format. Uniform random bytes of length >= 12 satisfy all three essentially
// always, and because this decoder registers as core.All it joins every UDP
// fallback scan -- so it adopted NetBIOS Name Service and DNS conversations and
// emitted Protobuf audit records for them.
//
// Same defect and same remedy as modbus: see
// internal/decoder/stream/modbus/modbus_test.go:7, where an MBAP header alone
// matched LDAP's BER framing.

// mustHex fails the test rather than returning an error, so a typo in a fixture
// below is not silently decoded as a short payload that happens to be rejected
// for the wrong reason.
func mustHex(tb testing.TB, s string) []byte {
	tb.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		tb.Fatalf("bad fixture hex: %v", err)
	}

	return b
}

// Payloads lifted from the RawPayload field of records this decoder actually
// produced from testdata/test.pcap and testdata/cip.pcap. Every one of them
// passes the statistical tests, which is why they were adopted.
const (
	// NetBIOS Name Service, UDP 137. The name is first-level encoded; netcap
	// decodes this traffic correctly in decoder/stream/discovery/nbns.go.
	nbnsRegistrationHex = "002585000000000100000000204550454a45444646444944424443434e46494641434143414341434143414341004320"

	// A second NBNS payload whose transaction ID is non-zero, so its rejection
	// cannot be attributed to a leading 0x00 alone.
	nbnsQueryHex = "4b9285000000000100000000204544464545474341434143414341434143414341434142"

	// DNS A query for www.cabanadosol.net, UDP 61349->53, and its response.
	// Transaction ID 0xa0f1 is what satisfied the varint-pattern test.
	dnsQueryHex    = "a0f101000001000000000000037777770b636162616e61646f736f6c036e65740000010001"
	dnsResponseHex = "a0f181800001000200000000037777770b636162616e61646f736f6c036e65740000010001c00c"
)

// TestIsProtobufDataRejectsForeignProtocols covers traffic eliminated at
// detection. These open with a 0x00 byte, which reads as field number 0, so
// they cannot be protobuf however their byte statistics look.
//
// Measured end to end: the collector produced 2 records from testdata/test.pcap
// and 18 from testdata/cip.pcap before the tag gate, and 0 from both after it.
// The fixtures here are reconstructed from the RawPayload of those records and
// are representative rather than byte-identical, so they pin the mechanism, not
// the exact counts. TestProtobufNoFalsePositivesCollector pins the counts.
func TestIsProtobufDataRejectsForeignProtocols(t *testing.T) {
	tests := []struct {
		name string
		hex  string
	}{
		{"nbns registration", nbnsRegistrationHex},
		{"nbns query", nbnsQueryHex},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := mustHex(t, tt.hex)

			if IsProtobufData(data) {
				t.Errorf("IsProtobufData accepted %d bytes of %s traffic", len(data), tt.name)
			}
		})
	}
}

// TestForeignProtocolsSurvivingDetectionStillProduceNoRecord is why processData
// no longer writes a record when parsing fails.
//
// A tag gate cannot be sufficient on its own, and DNS shows why: the
// transaction ID 0xa0f1 decodes as a structurally valid tag -- field number
// 3860, wire type 0 -- so these payloads pass detection and reach the parser,
// which then rejects them at the next tag. Whatever gets that far must produce
// nothing rather than a record carrying an ErrorMsg.
//
// On the current corpus the tag gate alone already takes the collector to zero
// records, so this second layer is defence in depth rather than the thing that
// removed a measured false positive.
func TestForeignProtocolsSurvivingDetectionStillProduceNoRecord(t *testing.T) {
	for _, tt := range []struct {
		name string
		hex  string
	}{
		{"dns query", dnsQueryHex},
		{"dns response", dnsResponseHex},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data := mustHex(t, tt.hex)

			if !IsProtobufData(data) {
				t.Skip("no longer reaches the parser; fold this case into the detection test above")
			}

			if _, err := DecodeMessages(data); err == nil {
				t.Errorf("DecodeMessages parsed %d bytes of %s traffic as protobuf", len(data), tt.name)
			}
		})
	}
}

// TestIsProtobufDataRejectsHighEntropyNoise covers the general case the
// fixtures above are instances of. Raising the entropy threshold could never
// have fixed this: the tightest payload that must still be accepted measures
// 3.278 bits and the lowest observed false positive 3.521.
func TestIsProtobufDataRejectsHighEntropyNoise(t *testing.T) {
	// Deterministic, and chosen so it has no valid opening tag: byte 0 is 0x00,
	// i.e. field number 0, which ParseMessage rejects at its first iteration.
	noise := make([]byte, 256)
	noise[0] = 0x00

	for i := 1; i < len(noise); i++ {
		noise[i] = byte((i*7 + 13) % 251)
	}

	if CalculateEntropy(noise) <= 3.0 {
		t.Fatalf("fixture is not high-entropy (%.3f); it would be rejected for the wrong reason",
			CalculateEntropy(noise))
	}

	if IsProtobufData(noise) {
		t.Error("IsProtobufData accepted high-entropy noise with an invalid opening tag")
	}
}

// TestIsProtobufDataAcceptsLengthPrefixedFraming guards the regression that the
// first version of this fix introduced. gRPC and custom protobuf-over-TCP
// prefix each message with a 4-byte big-endian length, so byte 0 is usually
// 0x00 and reads as field number 0. Checking only the raw form rejected the
// whole protobuf_tcp_addressbook.pcapng corpus, which
// TestProtobufPCAPExtraction/TCP_AddressBook caught.
func TestIsProtobufDataAcceptsLengthPrefixedFraming(t *testing.T) {
	var framed bytes.Buffer

	framed.Write([]byte{0x00, 0x00, 0x00, byte(len(validProtobufData))})
	framed.Write(validProtobufData)

	if !startsWithTag(validProtobufData) {
		t.Fatal("fixture is wrong: validProtobufData should open with a valid tag")
	}

	if startsWithTag(framed.Bytes()) {
		t.Fatal("fixture is wrong: the framed form should NOT open with a valid tag")
	}

	if !hasValidFirstTag(framed.Bytes()) {
		t.Error("hasValidFirstTag rejected length-prefixed protobuf; detection disagrees with processData")
	}
}

// TestStartsWithTagRejectsGroupWireTypes pins the deliberate exclusion of wire
// types 3 and 4. They are deprecated start/end group markers that ParseMessage
// does not implement, so accepting them at detection would only produce records
// it must then fail to parse.
func TestStartsWithTagRejectsGroupWireTypes(t *testing.T) {
	for _, wt := range []byte{3, 4, 6, 7} {
		tag := byte(1<<3) | wt // field number 1
		if startsWithTag([]byte{tag, 0x00, 0x00, 0x00}) {
			t.Errorf("startsWithTag accepted wire type %d", wt)
		}
	}

	for _, wt := range []byte{0, 1, 2, 5} {
		tag := byte(1<<3) | wt
		if !startsWithTag([]byte{tag, 0x00, 0x00, 0x00}) {
			t.Errorf("startsWithTag rejected wire type %d", wt)
		}
	}
}

// TestStartsWithTagRejectsFieldNumberZero covers the single condition that
// eliminated 16 of the 20 observed false positives on its own.
func TestStartsWithTagRejectsFieldNumberZero(t *testing.T) {
	for _, wt := range []byte{0, 1, 2, 5} {
		if startsWithTag([]byte{wt, 0xff, 0xff, 0xff}) {
			t.Errorf("startsWithTag accepted field number 0 with wire type %d", wt)
		}
	}
}
