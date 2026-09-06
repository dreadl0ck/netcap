package modbus

import (
	"encoding/hex"
	"slices"
	"strings"
	"testing"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/types"
)

func pduBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPDUSemantics(t *testing.T) {
	for _, tt := range []struct {
		name, pdu, role, bank string
		check                 func(*types.Modbus) bool
	}{
		{"coils request", "01ffff0001", "request", "coils", func(m *types.Modbus) bool { return m.HasAddress && m.Address == 65535 && m.Quantity == 1 }},
		{"bits response", "010181", "response", "coils", func(m *types.Modbus) bool {
			return !m.HasAddress && m.Quantity == 0 && slices.Equal(m.Values, []uint32{1, 0, 0, 0, 0, 0, 0, 1})
		}},
		{"discrete request", "02000007d0", "request", "discrete_inputs", func(m *types.Modbus) bool { return m.Quantity == 2000 }},
		{"holding request", "030000007d", "request", "holding_registers", func(m *types.Modbus) bool { return m.Quantity == 125 }},
		{"input response", "04041234ffff", "response", "input_registers", func(m *types.Modbus) bool {
			return !m.HasAddress && m.Quantity == 2 && slices.Equal(m.Values, []uint32{0x1234, 65535})
		}},
		{"coil write", "050010ff00", "unknown", "coils", func(m *types.Modbus) bool { return m.MessageRole == "unknown" && m.Address == 16 && m.Values[0] == 1 }},
		{"register write", "060010ffff", "response", "holding_registers", func(m *types.Modbus) bool { return m.Address == 16 && m.Values[0] == 65535 }},
		{"coils write", "0f00100009028101", "request", "coils", func(m *types.Modbus) bool {
			return m.Quantity == 9 && slices.Equal(m.Values, []uint32{1, 0, 0, 0, 0, 0, 0, 1, 1})
		}},
		{"registers write", "1000100002041234ffff", "request", "holding_registers", func(m *types.Modbus) bool { return slices.Equal(m.Values, []uint32{0x1234, 65535}) }},
		{"write ack", "1000100002", "response", "holding_registers", func(m *types.Modbus) bool { return m.Quantity == 2 && len(m.Values) == 0 }},
		{"mask", "160010ff0000ff", "unknown", "holding_registers", func(m *types.Modbus) bool {
			return m.AndMask == 0xff00 && m.OrMask == 255 && m.MessageRole == "unknown"
		}},
		{"read write", "170010000200200001021234", "request", "holding_registers", func(m *types.Modbus) bool {
			return m.HasReadAddress && m.ReadAddress == 16 && m.ReadQuantity == 2 && m.HasWriteAddress && m.WriteAddress == 32 && m.WriteQuantity == 1 && m.WriteValues[0] == 0x1234
		}},
		{"read write response", "17040001ffff", "response", "holding_registers", func(m *types.Modbus) bool {
			return !m.HasReadAddress && !m.HasWriteAddress && m.ReadQuantity == 2 && len(m.Values) == 2
		}},
		{"diagnostic", "08000012345678", "unknown", "", func(m *types.Modbus) bool {
			return m.HasDiagnostic && m.DiagnosticSubfunction == 0 && hex.EncodeToString(m.DiagnosticData) == "12345678"
		}},
		{"file read", "140706000100020002", "request", "file_records", func(m *types.Modbus) bool {
			r := m.FileRecords[0]
			return r.FileNumber == 1 && r.RecordNumber == 2 && r.RecordLength == 2 && r.ReferenceType == 6
		}},
		{"file response", "140605061234ffff", "response", "file_records", func(m *types.Modbus) bool {
			r := m.FileRecords[0]
			return r.FileNumber == 0 && r.RecordNumber == 0 && r.RecordLength == 2 && slices.Equal(r.Values, []uint32{0x1234, 65535})
		}},
		{"file write", "150b060001000200021234ffff", "unknown", "file_records", func(m *types.Modbus) bool { return m.MessageRole == "unknown" && len(m.FileRecords[0].Values) == 2 }},
		{"device request", "2b0e0400", "request", "", func(m *types.Modbus) bool {
			return m.MEIType == 14 && m.ReadDeviceIDCode == 4 && m.DeviceIDObjectID == 0
		}},
		{"device response", "2b0e0181ff0302000141010142", "response", "", func(m *types.Modbus) bool {
			return m.DeviceIDConformityLevel == 129 && m.DeviceIDMoreFollows && m.DeviceIDNextObjectID == 3 && len(m.DeviceIDObjects) == 2 && string(m.DeviceIDObjects[1].Value) == "B"
		}},
		{"exception status request", "07", "request", "", func(m *types.Modbus) bool {
			return !m.HasAddress && m.Quantity == 0 && len(m.Values) == 0
		}},
		{"exception status response", "0755", "response", "", func(m *types.Modbus) bool {
			return !m.HasAddress && slices.Equal(m.Values, []uint32{0x55})
		}},
		{"event counter request", "0b", "request", "", func(m *types.Modbus) bool { return len(m.Values) == 0 }},
		{"event counter response", "0b0000ffff", "response", "", func(m *types.Modbus) bool {
			return slices.Equal(m.Values, []uint32{0, 65535})
		}},
		{"event counter busy response", "0bffff0108", "response", "", func(m *types.Modbus) bool {
			return slices.Equal(m.Values, []uint32{65535, 0x0108})
		}},
		{"event log request", "0c", "request", "", func(m *types.Modbus) bool { return m.Quantity == 0 && len(m.Values) == 0 }},
		{"event log response", "0c08000001080121ff00", "response", "", func(m *types.Modbus) bool {
			return m.Quantity == 2 && slices.Equal(m.Values, []uint32{0, 0x0108, 0x0121, 0xff, 0})
		}},
		{"event log response without events", "0c06ffff00000000", "response", "", func(m *types.Modbus) bool {
			return m.Quantity == 0 && slices.Equal(m.Values, []uint32{65535, 0, 0})
		}},
		{"server id response", "1103ff00aa", "response", "", func(m *types.Modbus) bool {
			return m.Quantity == 3 && len(m.Values) == 0 && !m.HasAddress
		}},
		{"server id minimal response", "110111", "response", "", func(m *types.Modbus) bool { return m.Quantity == 1 }},
		{"fifo request", "180010", "request", "", func(m *types.Modbus) bool {
			return m.HasAddress && m.Address == 16 && m.Quantity == 0 && len(m.Values) == 0
		}},
		{"fifo response", "18000600021234ffff", "response", "", func(m *types.Modbus) bool {
			return !m.HasAddress && m.Quantity == 2 && slices.Equal(m.Values, []uint32{0x1234, 65535})
		}},
		{"fifo empty response", "1800020000", "response", "", func(m *types.Modbus) bool {
			return m.Quantity == 0 && len(m.Values) == 0
		}},
		{"fifo full response", "18" + "0040" + "001f" + strings.Repeat("0001", 31), "response", "", func(m *types.Modbus) bool {
			return m.Quantity == 31 && len(m.Values) == 31 && m.Values[30] == 1
		}},
		{"exception", "8302", "unknown", "holding_registers", func(m *types.Modbus) bool {
			return m.MessageRole == "response" && m.Exception && m.ExceptionCode == 2 && m.FunctionCode == 3
		}},
		{"exception status exception", "8704", "unknown", "", func(m *types.Modbus) bool {
			return m.MessageRole == "response" && m.Exception && m.FunctionCode == 7 && m.ExceptionCode == 4
		}},
		{"event counter exception", "8b01", "response", "", func(m *types.Modbus) bool {
			return m.Exception && m.FunctionCode == 11 && m.ExceptionCode == 1
		}},
		{"event log exception", "8c01", "response", "", func(m *types.Modbus) bool {
			return m.Exception && m.FunctionCode == 12 && m.ExceptionCode == 1
		}},
		{"server id exception", "9101", "unknown", "", func(m *types.Modbus) bool {
			return m.MessageRole == "response" && m.Exception && m.FunctionCode == 17 && m.ExceptionCode == 1
		}},
		{"fifo exception", "9802", "unknown", "", func(m *types.Modbus) bool {
			return m.MessageRole == "response" && m.Exception && m.FunctionCode == 24 && m.ExceptionCode == 2
		}},
		{"ambiguous read shape", "0103000001", "unknown", "coils", func(m *types.Modbus) bool { return m.MessageRole == "unknown" && !m.HasAddress && len(m.Values) == 0 }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := parsePDU(pduBytes(t, tt.pdu), tt.role)
			if m.ParseStatus != "valid" || m.Bank != tt.bank || !tt.check(m) {
				t.Fatalf("unexpected PDU: %+v", m)
			}
		})
	}
}

func TestPDUMalformed(t *testing.T) {
	for _, tt := range []struct{ pdu, role string }{
		{"", "request"}, {"01", "request"}, {"0100000000", "request"}, {"01000007d1", "request"},
		{"03ffff0002", "request"}, {"030000007e", "request"}, {"030000000100", "request"},
		{"0300", "response"}, {"0303000102", "response"}, {"03040001", "response"},
		{"0500000001", "request"}, {"060000", "response"}, {"0f000000090201ff", "request"},
		{"0fffff0002", "response"}, {"100000007c", "response"}, {"1000000002020001", "request"},
		{"160000ffff", "request"}, {"17ffff000200000001020001", "request"},
		{"1700000001ffff0002020001", "request"}, {"17000000010000000000", "request"},
		{"1703000102", "response"}, {"08000100000000", "request"}, {"08000000", "response"},
		{"140706000000000001", "request"}, {"140706000127100001", "request"},
		{"14070600010000007e", "request"}, {"14070600010000007d", "request"},
		{"140706000100000000", "request"}, {"140403060001", "request"},
		{"140403050001", "response"}, {"140402060001", "response"},
		{"1509060001000000020001", "request"}, {"1500", "request"},
		{"2b", "request"}, {"2b0e0000", "request"}, {"2b0e010000", "request"},
		{"2b0e0100000000", "response"}, {"2b0e0101010000", "response"},
		{"2b0e0101000001000241", "response"}, {"2b0e010100000000", "response"},
		{"2b0e0401000000", "response"}, {"8300", "response"}, {"830200", "response"}, {"8302", "request"},
		{"0700", "request"}, {"07", "response"}, {"075500", "response"},
		{"0b00", "request"}, {"0b000000", "response"}, {"0b0000000000", "response"},
		{"0b00010000", "response"}, {"0bfffe0000", "response"},
		{"0c00", "request"}, {"0c060000000000", "response"}, {"0c0800000000000020", "response"},
		{"0c06000100000000", "response"}, {"0c07ffff000000002000", "response"},
		{"1100", "request"}, {"11", "response"}, {"1100", "response"},
		{"1102ff", "response"}, {"1101ffaa", "response"},
		{"18", "request"}, {"1800", "request"}, {"18001000", "request"},
		{"180006", "response"}, {"18000400021234ffff", "response"},
		{"18000600021234", "response"}, {"180006000212340000ffff", "response"},
		{"18" + "0042" + "0020" + strings.Repeat("0001", 32), "response"},
		{"87", "response"}, {"8b", "response"}, {"9800", "response"}, {"9801", "request"},
	} {
		t.Run(tt.pdu+tt.role, func(t *testing.T) {
			m := parsePDU(pduBytes(t, tt.pdu), tt.role)
			if m.ParseStatus != "malformed" || m.ParseError == "" || m.HasAddress || len(m.Values) != 0 {
				t.Fatalf("unexpected result: %+v", m)
			}
		})
	}
	for _, pdu := range []string{"09", "0a01", "0d0102", "410102", "2b0d0102"} {
		if m := parsePDU(pduBytes(t, pdu), "unknown"); m.ParseStatus != "unsupported" {
			t.Fatalf("unsupported: %+v", m)
		}
	}
}

// TestPDURoleInference pins the orientation of the function codes whose request
// and response layouts never share a length, in contrast to FC1-4/20.
func TestPDURoleInference(t *testing.T) {
	for _, tt := range []struct{ pdu, role string }{
		{"07", "request"}, {"0755", "response"},
		{"0b", "request"}, {"0b0000ffff", "response"},
		{"0c", "request"}, {"0c06ffff00000000", "response"},
		{"11", "request"}, {"1102ff00", "response"},
		{"180010", "request"}, {"1800020000", "response"}, {"18000600021234ffff", "response"},
	} {
		t.Run(tt.pdu, func(t *testing.T) {
			m := parsePDU(pduBytes(t, tt.pdu), "unknown")
			if m.ParseStatus != "valid" || m.MessageRole != tt.role {
				t.Fatalf("unexpected role: %+v", m)
			}
		})
	}
	// Both layouts fit these bytes, so the orientation stays unresolved.
	for _, pdu := range []string{"0103000001", "0203000001", "150b060001000200021234ffff"} {
		if m := parsePDU(pduBytes(t, pdu), "unknown"); m.ParseStatus != "valid" || m.MessageRole != "unknown" {
			t.Fatalf("expected ambiguity: %+v", m)
		}
	}
}

func TestStructuredPayloadDisabledAndRoles(t *testing.T) {
	for _, midstream := range []bool{false, true} {
		m := reader(t)
		decoderconfig.Instance.IncludePayloads = false
		decoderconfig.Instance.AllowMissingInit = true
		m.conversation.TCPHandshakeComplete = !midstream
		m.conversation.ClientData = core.DataFragments{fragment(wire(1, 6, 0, 0, 0, 42), 100, false)}
		m.conversation.ServerData = core.DataFragments{fragment(wire(1, 6, 0, 0, 0, 42), 200, true)}
		if midstream {
			m.conversation.ClientData = append(core.DataFragments{&core.StreamData{SkippedBytes: -1}}, m.conversation.ClientData...)
		}
		got := records(m)
		if len(got) != 2 {
			t.Fatal(got)
		}
		for _, r := range got {
			if r.Transport != "tcp" || r.ParseStatus != "valid" || len(r.Payload) != 0 || !r.HasAddress || r.Values[0] != 42 {
				t.Fatalf("structured without payload: %+v", r)
			}
		}
		if midstream {
			if got[0].MessageRole != "unknown" || got[1].MessageRole != "unknown" || got[1].CorrelationStatus != "ambiguous" {
				t.Fatal(got)
			}
		} else if got[0].MessageRole != "request" || got[1].MessageRole != "response" || got[1].CorrelationStatus != "matched" || got[1].ResponseLatency != 100 {
			t.Fatal(got)
		}
	}
}

func FuzzParsePDU(f *testing.F) {
	for _, b := range [][]byte{{3, 0, 0, 0, 1}, {0x83, 2}, {20, 7, 6, 0, 1, 0, 0, 0, 1}, {43, 14, 1, 1, 0, 0, 0},
		{7, 0x55}, {11, 0, 0, 1, 8}, {12, 8, 0, 0, 1, 8, 1, 33, 32, 0}, {17, 3, 255, 0, 170}, {24, 0, 6, 0, 2, 18, 52, 255, 255}} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, role := range []string{"request", "response", "unknown"} {
			m := parsePDU(b, role)
			if m.ParseStatus != "valid" && m.ParseStatus != "malformed" && m.ParseStatus != "unsupported" {
				t.Fatal(m)
			}
		}
	})
}

func TestMalformedPDUDoesNotStopFraming(t *testing.T) {
	m := reader(t)
	decoderconfig.Instance.IncludePayloads = false
	data := append(wire(1, 16, 0, 0, 0, 2, 2, 0, 1), wire(2, 3, 0, 0, 0, 1)...)
	m.conversation.ClientData = core.DataFragments{fragment(data, 100, false)}
	got := records(m)
	if len(got) != 2 || got[0].ParseStatus != "malformed" || got[1].ParseStatus != "valid" || got[1].Quantity != 1 {
		t.Fatal(got)
	}
}
