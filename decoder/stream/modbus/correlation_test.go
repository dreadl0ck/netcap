package modbus

import (
	"bytes"
	"fmt"
	"testing"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
)

func TestTCPTransactions(t *testing.T) {
	type event struct {
		id, unit  int32
		pdu, role string
		timestamp int64
		server    bool
		status    string
	}
	req := event{1, 1, "0300100002", "request", 100, false, "not_applicable"}
	res := event{1, 1, "03040001ffff", "response", 200, true, "matched"}
	for _, tt := range []struct {
		name   string
		events []event
	}{
		{"match", []event{req, res}},
		{"reuse", []event{req, res, {1, 1, "0300200002", "request", 300, false, "not_applicable"}, {1, 1, "030400010002", "response", 400, true, "matched"}}},
		{"outstanding", []event{req, {2, 1, "0400100001", "request", 110, false, "not_applicable"}, {2, 1, "04020002", "response", 120, true, "matched"}, res}},
		{"duplicate", []event{req, {1, 1, "0300100002", "request", 110, false, "ambiguous"}, {1, 1, "03040001ffff", "response", 200, true, "ambiguous"}, {1, 1, "03040001ffff", "response", 210, true, "ambiguous"}}},
		{"duplicate different unit", []event{req, {1, 2, "0300100002", "request", 110, false, "ambiguous"}, {1, 1, "03040001ffff", "response", 200, true, "ambiguous"}}},
		{"missing", []event{{1, 1, "03040001ffff", "response", 200, true, "unmatched"}}},
		{"wrong unit", []event{req, {1, 2, "03040001ffff", "response", 200, true, "unmatched"}}},
		{"wrong function", []event{req, {1, 1, "04040001ffff", "response", 200, true, "unmatched"}}},
		{"wrong count", []event{req, {1, 1, "03020001", "response", 200, true, "unmatched"}}},
		{"same direction", []event{req, {1, 1, "03040001ffff", "response", 200, false, "unmatched"}}},
		{"negative latency", []event{req, {1, 1, "03040001ffff", "response", 99, true, "unmatched"}}},
		{"timeout", []event{req, {1, 1, "03040001ffff", "response", requestTimeout + 101, true, "unmatched"}}},
		{"exception", []event{req, {1, 1, "8302", "response", 200, true, "matched"}}},
		{"wrong exception", []event{req, {1, 1, "8402", "response", 200, true, "unmatched"}}},
		{"malformed duplicate", []event{req, {1, 1, "03", "request", 110, false, "not_applicable"}, {1, 1, "03040001ffff", "response", 200, true, "ambiguous"}}},
		{"unknown duplicate", []event{req, {1, 1, "0600000001", "unknown", 110, false, "ambiguous"}, {1, 1, "03040001ffff", "response", 200, true, "ambiguous"}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := tcpCorrelation{pending: make(map[int32]pendingRequest)}
			for i, e := range tt.events {
				m := parsePDU(pduBytes(t, e.pdu), e.role)
				m.TransactionID, m.UnitID, m.Timestamp = e.id, e.unit, e.timestamp
				c.observe(m, e.server)
				if m.CorrelationStatus != e.status {
					t.Fatalf("event %d: want %s got %+v", i, e.status, m)
				}
				if e.role == "response" {
					if e.status == "matched" {
						if m.RequestTimestamp == 0 || m.ResponseLatency != m.Timestamp-m.RequestTimestamp || m.ResponseLatency < 0 {
							t.Fatal(m)
						}
						if !m.Exception && !m.HasAddress {
							t.Fatalf("missing enrichment: %+v", m)
						}
					} else if m.HasAddress || m.RequestTimestamp != 0 || m.ResponseLatency != 0 {
						t.Fatalf("unmatched enrichment: %+v", m)
					}
				}
			}
		})
	}
}

func TestCorrelationContents(t *testing.T) {
	for _, tt := range []struct {
		request, response string
		matched           bool
	}{
		{"0100100009", "01020101", true}, {"0100100009", "01020181", false},
		{"050010ff00", "050010ff00", true}, {"050010ff00", "0500100000", false},
		{"0600101234", "0600111234", false},
		{"0f00100009020101", "0f00100009", true}, {"0f00100009020101", "0f00100008", false},
		{"1000100001021234", "1000100001", true},
		{"160010ff0000ff", "160010ff0000ff", true}, {"160010ff0000ff", "160010ff000000", false},
		{"170010000200200001021234", "17040001ffff", true},
		{"170010000200200001021234", "17020001", false},
		{"0800001234", "0800001234", true}, {"0800001234", "0800001235", false},
		{"08000b0000", "08000bffff", true}, {"0800040000", "0800040000", false},
		{"140706000100020002", "140605061234ffff", true},
		{"140706000100020002", "140403061234", false},
		{"1509060001000200011234", "1509060001000200011234", true},
		{"1509060001000200011234", "1509060001000200011235", false},
		{"2b0e0400", "2b0e0481000001000141", true},
		{"2b0e0400", "2b0e0481000001010141", false},
		{"180010", "18000600021234ffff", true},
	} {
		t.Run(tt.request+"/"+tt.response, func(t *testing.T) {
			c := tcpCorrelation{pending: make(map[int32]pendingRequest)}
			r, m := parsePDU(pduBytes(t, tt.request), "request"), parsePDU(pduBytes(t, tt.response), "response")
			r.Timestamp, m.Timestamp = 100, 200
			if r.ParseStatus != "valid" || m.ParseStatus != "valid" {
				t.Fatalf("bad test PDUs: %+v %+v", r, m)
			}
			c.observe(r, false)
			c.observe(m, true)
			if (m.CorrelationStatus == "matched") != tt.matched {
				t.Fatal(m)
			}
			if tt.matched {
				switch m.FunctionCode {
				case 1:
					if len(m.Values) != 9 || m.Quantity != 9 || m.Address != 16 {
						t.Fatal(m)
					}
				case 23:
					if !m.HasReadAddress || m.ReadAddress != 16 || !m.HasWriteAddress || m.WriteAddress != 32 || m.WriteValues[0] != 0x1234 {
						t.Fatal(m)
					}
				case 20:
					if m.FileRecords[0].FileNumber != 1 || m.FileRecords[0].RecordNumber != 2 {
						t.Fatal(m)
					}
				case 24:
					// The FIFO pointer comes from the request, the queue from
					// the response.
					if !m.HasAddress || m.Address != 16 || m.Quantity != 2 || len(m.Values) != 2 {
						t.Fatal(m)
					}
				}
			}
		})
	}
}

func TestPendingBound(t *testing.T) {
	c := tcpCorrelation{pending: make(map[int32]pendingRequest)}
	for i := 0; i <= maxPendingRequests; i++ {
		m := parsePDU([]byte{3, 0, 0, 0, 1}, "request")
		m.TransactionID, m.Timestamp = int32(i), 100
		c.observe(m, false)
	}
	if len(c.pending) != maxPendingRequests || !c.saturated {
		t.Fatalf("pending=%d saturated=%v", len(c.pending), c.saturated)
	}
	m := parsePDU([]byte{3, 2, 0, 1}, "response")
	m.Timestamp = 200
	c.observe(m, true)
	if m.CorrelationStatus != "ambiguous" {
		t.Fatal(m)
	}
	r := parsePDU([]byte{3, 0, 0, 0, 1}, "request")
	r.Timestamp = requestTimeout + 101
	c.observe(r, false)
	m = parsePDU([]byte{3, 2, 0, 1}, "response")
	m.Timestamp = requestTimeout + 201
	c.observe(m, true)
	if m.CorrelationStatus != "matched" || len(c.pending) != 0 || c.saturated {
		t.Fatal(m)
	}
}

func TestMidstreamShapeCorrelation(t *testing.T) {
	m := reader(t)
	// The first observed direction is actually the server; ports are not evidence.
	start := fragment(nil, 1, false)
	start.SkippedBytes = -1
	m.conversation.ClientData = core.DataFragments{start, fragment(wire(9, 3, 2, 0, 7), 100, false), fragment(wire(1, 3, 2, 0, 42), 300, false)}
	m.conversation.ServerData = core.DataFragments{fragment(wire(1, 3, 0, 10, 0, 1), 200, true)}
	decoderconfig.Instance.AllowMissingInit = true
	got := records(m)
	if len(got) != 3 || got[0].MessageRole != "response" || got[0].CorrelationStatus != "unmatched" || got[1].MessageRole != "request" || got[2].CorrelationStatus != "matched" || got[2].Address != 10 {
		t.Fatal(got)
	}
}

func TestTCPRolesRequireHandshake(t *testing.T) {
	for _, handshake := range []bool{false, true} {
		t.Run(fmt.Sprint(handshake), func(t *testing.T) {
			m := reader(t)
			m.conversation.TCPHandshakeComplete = handshake
			// A single write echoes its request, so without an observed
			// handshake the client/server assignment is not evidence of a role.
			echo := wire(1, 5, 0, 16, 0xff, 0)
			m.conversation.ClientData = core.DataFragments{fragment(echo, 100, false)}
			m.conversation.ServerData = core.DataFragments{fragment(echo, 200, true)}
			got := records(m)
			roles, status := []string{"unknown", "unknown"}, []string{"ambiguous", "ambiguous"}
			if handshake {
				roles, status = []string{"request", "response"}, []string{"not_applicable", "matched"}
			}
			if len(got) != 2 {
				t.Fatal(got)
			}
			for i, r := range got {
				if r.MessageRole != roles[i] || r.CorrelationStatus != status[i] {
					t.Fatalf("record %d: %+v", i, r)
				}
			}
		})
	}
}

// An FC15 request carries up to 1968 values that no response ever consults.
func TestPendingRequestDropsBulkValues(t *testing.T) {
	r := parsePDU(append([]byte{15, 0, 0, 0x07, 0xb0, 246}, bytes.Repeat([]byte{0xff}, 246)...), "request")
	if r.ParseStatus != "valid" || len(r.Values) != 1968 {
		t.Fatalf("bad request: %+v", r)
	}
	c := tcpCorrelation{pending: make(map[int32]pendingRequest)}
	c.observe(r, false)
	if p := c.pending[0]; p.values != nil || p.quantity != 1968 {
		t.Fatalf("retained %d values", len(c.pending[0].values))
	}
	m := parsePDU([]byte{15, 0, 0, 0x07, 0xb0}, "response")
	m.Timestamp = 1
	c.observe(m, true)
	if m.CorrelationStatus != "matched" {
		t.Fatalf("%+v", m)
	}
}

func TestGapPreventsCorrelation(t *testing.T) {
	m := reader(t)
	request, response := wire(1, 3, 0, 10, 0, 1), wire(1, 3, 2, 0, 42)
	gap := fragment(nil, 150, false)
	gap.SkippedBytes = 12
	m.conversation.ClientData = core.DataFragments{fragment(request, 100, false), gap}
	m.conversation.ServerData = core.DataFragments{fragment(response, 200, true)}
	got := records(m)
	// The gap may hide the real response, so the request is no longer evidence.
	// The client direction never resumed, so its marker reports at the end of
	// the conversation, carrying the timestamp of the gap.
	if len(got) != 3 || !isLoss(got[2], 12, "tcp") || got[2].Timestamp != 150 ||
		got[1].CorrelationStatus != "ambiguous" || got[1].HasAddress || got[1].RequestTimestamp != 0 {
		t.Fatal(got)
	}
	// A request destroyed inside the gap was never observed, so its transaction
	// ID is unmarked and a response to it would be credited to the post-gap
	// request reusing that ID.
	m = reader(t)
	m.conversation.TCPHandshakeComplete = true
	m.conversation.ClientData = core.DataFragments{gap, fragment(request, 300, false)}
	m.conversation.ServerData = core.DataFragments{fragment(response, 400, true)}
	got = records(m)
	if len(got) != 3 || !isLoss(got[0], 12, "tcp") || got[1].MessageRole != "request" ||
		got[2].CorrelationStatus != "ambiguous" || got[2].HasAddress || got[2].RequestTimestamp != 0 {
		t.Fatal(got)
	}
	// Once such a request would have timed out, correlation resumes.
	m = reader(t)
	m.conversation.TCPHandshakeComplete = true
	late := requestTimeout + 200
	m.conversation.ClientData = core.DataFragments{gap, fragment(request, late, false)}
	m.conversation.ServerData = core.DataFragments{fragment(response, late+100, true)}
	got = records(m)
	if len(got) != 3 || !isLoss(got[0], 12, "tcp") || got[2].CorrelationStatus != "matched" || got[2].Address != 10 {
		t.Fatal(got)
	}
}
