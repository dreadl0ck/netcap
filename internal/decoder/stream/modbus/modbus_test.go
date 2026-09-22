package modbus

import (
	"bytes"
	"testing"
)

// TestCanDecodeRejectsForeignProtocols pins the detection tightening. An MBAP
// header alone is a weak signature: LDAP's BER framing satisfies every field of
// it, and adopting those conversations produced Modbus records for traffic that
// is not Modbus.
func TestCanDecodeRejectsForeignProtocols(t *testing.T) {
	// Observed LDAP over IPv6: SEQUENCE, long-form length, then INTEGER
	// messageID. Read as MBAP this is protocol ID 0, length 204, unit 2,
	// function code 1.
	ldap := append([]byte{0x30, 0x84, 0x00, 0x00, 0x00, 0xcc, 0x02, 0x01},
		bytes.Repeat([]byte{0x04, 0x01, 0x61}, 100)...)

	for _, tt := range []struct {
		name string
		data []byte
		want bool
	}{
		{"LDAP BER header", ldap[:8], false},
		{"LDAP BER with a complete declared length", ldap[:210], false},
		{"LDAP BER truncated mid-body", ldap[:64], false},
		// Genuine Modbus: read holding registers, request and response.
		{"read request", []byte{0, 1, 0, 0, 0, 6, 1, 3, 0, 1, 0, 1}, true},
		{"read response", []byte{0, 1, 0, 0, 0, 5, 1, 3, 2, 0, 0}, true},
		{"write request", []byte{0, 2, 0, 0, 0, 6, 1, 6, 0, 0, 0, 1}, true},
		{"exception response", []byte{0, 3, 0, 0, 0, 3, 1, 0x83, 2}, true},
		// A declared ADU that has not fully arrived is not yet evidence; the
		// TCP selector concatenates a direction before asking.
		{"incomplete ADU", []byte{0, 1, 0, 0, 0, 6, 1, 3, 0, 1}, false},
		{"nonzero protocol id", []byte{0, 1, 0, 1, 0, 6, 1, 3, 0, 1, 0, 1}, false},
		{"unknown function code", []byte{0, 1, 0, 0, 0, 6, 1, 0x63, 0, 1, 0, 1}, false},
		{"body that does not decode", []byte{0, 1, 0, 0, 0, 6, 1, 3, 0, 1, 0xff, 0xff}, false},
		{"too short", []byte{0, 1, 0, 0, 0, 6, 1}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := canDecodeModbus(tt.data); got != tt.want {
				t.Fatalf("canDecodeModbus = %v, want %v", got, tt.want)
			}
		})
	}
}
