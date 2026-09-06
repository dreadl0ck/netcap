package io

import (
	"runtime/debug"
	"testing"

	"github.com/dreadl0ck/netcap/encoder"
	"github.com/dreadl0ck/netcap/types"
)

// TestAuditRecordSerializationOnZeroValue guards against nil dereferences in the
// serialization helpers. Optional nested messages are nil whenever the protocol
// did not carry them, which is the common case rather than an edge case: BFD
// packets without authentication used to segfault the whole capture here.
func TestAuditRecordSerializationOnZeroValue(t *testing.T) {
	// Encode() dereferences the encoder config, which the --encode path installs.
	encoder.SetConfig(&encoder.Config{ZScore: true})

	covered := 0

	for num, name := range types.Type_name {
		typ := types.Type(num)
		if typ == types.Type_NC_Header {
			continue
		}

		record, ok := InitRecord(typ).(types.AuditRecord)
		if !ok {
			// Not every enum entry has a registered audit record implementation.
			continue
		}
		covered++

		t.Run(name, func(t *testing.T) {
			// Recover so one broken type does not hide the rest.
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic: %v\n%s", r, debug.Stack())
				}
			}()

			header := record.CSVHeader()
			values := record.CSVRecord()
			if len(header) != len(values) {
				t.Errorf("CSVHeader has %d fields, CSVRecord has %d", len(header), len(values))
			}
			if encoded := record.Encode(); encoded == nil && len(header) > 0 {
				t.Error("Encode returned nil")
			}
			if _, err := record.JSON(); err != nil {
				t.Errorf("JSON: %v", err)
			}
			record.Time()
			record.Src()
			record.Dst()
			record.NetcapType()
			record.SetPacketContext(&types.PacketContext{})

			// Prometheus panics when the label cardinality of the vector does
			// not match the values Inc() derives from CSVRecord. Calling it
			// twice is safe: WithLabelValues returns the same child.
			record.Inc()
			record.Inc()
		})
	}

	if covered < 50 {
		t.Fatalf("only %d audit record types covered, expected the full set", covered)
	}
}

// TestBFDNilAuthHeader pins the specific regression: BFD without authentication.
func TestBFDNilAuthHeader(t *testing.T) {
	bfd := &types.BFD{Timestamp: 1, AuthPresent: false}
	if bfd.AuthHeader != nil {
		t.Fatal("expected a nil AuthHeader")
	}
	if got := bfd.CSVRecord(); got[len(got)-1] != "" {
		t.Errorf("AuthHeader field = %q, want empty", got[len(got)-1])
	}

	withAuth := &types.BFD{
		Timestamp:   1,
		AuthPresent: true,
		AuthHeader:  &types.BFDAuthHeader{AuthType: 2, KeyID: 3, SequenceNumber: 4, Data: []byte{0xab}},
	}
	if got := withAuth.CSVRecord(); got[len(got)-1] == "" {
		t.Error("populated AuthHeader must still be serialized")
	}
}
