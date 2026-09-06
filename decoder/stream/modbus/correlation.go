package modbus

import (
	"bytes"
	"slices"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

const (
	maxPendingRequests = 1024
	requestTimeout     = int64(30 * time.Second)
)

// pendingRequest keeps only the request evidence a later response needs.
// Retaining the record itself would pin its payload and value slice: a single
// FC15 request carries up to 1968 values, so a saturated map would hold
// megabytes per conversation.
type pendingRequest struct {
	timestamp                                   int64
	unitID, functionCode                        int32
	address, quantity, andMask, orMask          uint32
	readAddress, readQuantity                   uint32
	writeAddress, writeQuantity                 uint32
	diagnosticSubfunction                       uint32
	meiType, readDeviceIDCode, deviceIDObjectID uint32
	hasAddress, hasReadAddress, hasWriteAddress bool
	// Only single writes are compared against their echo; bulk write values are
	// never read back, so they are not stored.
	values         []uint32
	writeValues    []uint32
	diagnosticData []byte
	fileRecords    []*types.ModbusFileRecord
	server         bool
	ambiguous      bool
}

func newPendingRequest(m *types.Modbus, server bool) pendingRequest {
	p := pendingRequest{
		timestamp: m.Timestamp, unitID: m.UnitID, functionCode: m.FunctionCode,
		address: m.Address, quantity: m.Quantity, andMask: m.AndMask, orMask: m.OrMask,
		readAddress: m.ReadAddress, readQuantity: m.ReadQuantity,
		writeAddress: m.WriteAddress, writeQuantity: m.WriteQuantity,
		diagnosticSubfunction: m.DiagnosticSubfunction,
		meiType:               m.MEIType, readDeviceIDCode: m.ReadDeviceIDCode, deviceIDObjectID: m.DeviceIDObjectID,
		hasAddress: m.HasAddress, hasReadAddress: m.HasReadAddress, hasWriteAddress: m.HasWriteAddress,
		writeValues: m.WriteValues, diagnosticData: m.DiagnosticData, fileRecords: m.FileRecords,
		server: server,
	}
	if m.FunctionCode == 5 || m.FunctionCode == 6 {
		p.values = m.Values
	}
	return p
}

type tcpCorrelation struct {
	pending   map[int32]pendingRequest
	watermark int64
	// After saturation, suppress matches for a timeout rather than evicting
	// evidence that could distinguish a duplicate from a new transaction.
	saturated   bool
	saturatedAt int64
	// A capture gap suppresses matches the same way, because a request the gap
	// destroyed left no entry to mark.
	lost   bool
	lostAt int64
}

// lose marks every outstanding request after a capture gap: its response may
// have passed unseen, so a later response reusing the transaction ID is not
// evidence of a match. A request destroyed inside the gap was never observed at
// all, so its transaction ID cannot be marked and a response to it would
// otherwise be credited to a post-gap request reusing that ID. Responses are
// therefore ambiguous until such a request would have timed out. Only a gap in
// the response direction leaves post-gap requests immediately safe, and roles
// are known here only when the handshake was observed, so the distinction is
// not made.
func (c *tcpCorrelation) lose(timestamp int64) {
	if timestamp > c.watermark {
		c.watermark = timestamp
	}
	c.lost, c.lostAt = true, c.watermark
	for id, p := range c.pending {
		p.ambiguous = true
		c.pending[id] = p
	}
}

func (c *tcpCorrelation) observe(m *types.Modbus, server bool) {
	if m.Timestamp > c.watermark {
		c.watermark = m.Timestamp
	}
	for id, p := range c.pending {
		if c.watermark >= p.timestamp && uint64(c.watermark)-uint64(p.timestamp) > uint64(requestTimeout) {
			delete(c.pending, id)
		}
	}
	if c.saturated && c.watermark >= c.saturatedAt && uint64(c.watermark)-uint64(c.saturatedAt) > uint64(requestTimeout) {
		c.saturated = false
	}
	if c.lost && c.watermark >= c.lostAt && uint64(c.watermark)-uint64(c.lostAt) > uint64(requestTimeout) {
		c.lost = false
	}
	if m.MessageRole == "unknown" {
		m.CorrelationStatus = "ambiguous"
		if p, ok := c.pending[m.TransactionID]; ok {
			p.ambiguous = true
			c.pending[m.TransactionID] = p
		}
		return
	}
	if m.MessageRole == "response" {
		m.CorrelationStatus = "unmatched"
	}
	if m.ParseStatus != "valid" {
		if m.MessageRole == "request" {
			if p, ok := c.pending[m.TransactionID]; ok {
				p.ambiguous = true
				c.pending[m.TransactionID] = p
			}
		}
		return
	}
	if m.MessageRole == "request" {
		// Requests are emitted immediately; correlation describes responses, not
		// a promise that a response will arrive later.
		if p, ok := c.pending[m.TransactionID]; ok {
			// Keep duplicate ambiguity alive until all recent requests expire.
			if m.Timestamp > p.timestamp {
				p = newPendingRequest(m, p.server)
			}
			p.ambiguous = true
			c.pending[m.TransactionID] = p
			m.CorrelationStatus = "ambiguous"
			return
		}
		if c.saturated || len(c.pending) >= maxPendingRequests {
			c.saturated, c.saturatedAt = true, c.watermark
			m.CorrelationStatus = "ambiguous"
			return
		}
		c.pending[m.TransactionID] = newPendingRequest(m, server)
		return
	}
	if c.saturated || c.lost {
		m.CorrelationStatus = "ambiguous"
		return
	}
	p, ok := c.pending[m.TransactionID]
	if !ok {
		return
	}
	if p.ambiguous {
		m.CorrelationStatus = "ambiguous"
		return
	}
	if p.server == server || p.unitID != m.UnitID || p.functionCode != m.FunctionCode {
		return
	}
	if m.Timestamp < p.timestamp || uint64(m.Timestamp)-uint64(p.timestamp) > uint64(requestTimeout) {
		return
	}
	if !compatibleResponse(&p, m) {
		return
	}
	delete(c.pending, m.TransactionID)
	enrichResponse(&p, m)
}

// enrichResponse marks a response as matched and copies over the request
// context the response wire format omits.
func enrichResponse(r *pendingRequest, m *types.Modbus) {
	m.CorrelationStatus, m.RequestTimestamp, m.ResponseLatency = "matched", r.timestamp, m.Timestamp-r.timestamp
	if m.Exception {
		return
	}
	switch m.FunctionCode {
	case 1, 2, 3, 4:
		m.HasAddress, m.Address, m.Quantity = r.hasAddress, r.address, r.quantity
		m.Values = m.Values[:r.quantity]
	case 23:
		m.HasReadAddress, m.ReadAddress, m.ReadQuantity = r.hasReadAddress, r.readAddress, r.readQuantity
		m.HasWriteAddress, m.WriteAddress, m.WriteQuantity = r.hasWriteAddress, r.writeAddress, r.writeQuantity
		m.WriteValues = slices.Clone(r.writeValues)
	case 20:
		for i, record := range m.FileRecords {
			record.FileNumber, record.RecordNumber = r.fileRecords[i].FileNumber, r.fileRecords[i].RecordNumber
		}
	case 24:
		// The response carries the queue contents, the request the pointer.
		m.HasAddress, m.Address = r.hasAddress, r.address
	}
}

func compatibleResponse(r *pendingRequest, m *types.Modbus) bool {
	if m.Exception {
		return true
	}
	switch m.FunctionCode {
	case 1, 2:
		if len(m.Values) != int((r.quantity+7)/8)*8 {
			return false
		}
		for _, bit := range m.Values[r.quantity:] {
			if bit != 0 {
				return false
			}
		}
		return true
	case 3, 4:
		return m.Quantity == r.quantity
	case 5, 6:
		return m.Address == r.address && slices.Equal(m.Values, r.values)
	case 15, 16:
		return m.Address == r.address && m.Quantity == r.quantity
	case 22:
		return m.Address == r.address && m.AndMask == r.andMask && m.OrMask == r.orMask
	case 23:
		return m.ReadQuantity == r.readQuantity
	case 8:
		if m.DiagnosticSubfunction != r.diagnosticSubfunction {
			return false
		}
		switch r.diagnosticSubfunction {
		case 0, 1, 3, 10, 20:
			return bytes.Equal(m.DiagnosticData, r.diagnosticData)
		case 4:
			return false // Force Listen Only Mode has no response.
		}
		return true
	case 20, 21:
		if len(m.FileRecords) != len(r.fileRecords) {
			return false
		}
		for i, record := range m.FileRecords {
			q := r.fileRecords[i]
			if record.RecordLength != q.RecordLength || record.ReferenceType != q.ReferenceType {
				return false
			}
			if m.FunctionCode == 21 && (record.FileNumber != q.FileNumber || record.RecordNumber != q.RecordNumber || !slices.Equal(record.Values, q.Values)) {
				return false
			}
		}
		return true
	case 7, 11, 12, 17, 24:
		// These responses echo nothing from the request, so the transaction,
		// unit and function code already matched are the only evidence.
		return true
	case 43:
		if m.MEIType != r.meiType || m.ReadDeviceIDCode != r.readDeviceIDCode {
			return false
		}
		if r.readDeviceIDCode == 4 {
			return len(m.DeviceIDObjects) == 1 && m.DeviceIDObjects[0].ID == r.deviceIDObjectID
		}
		return len(m.DeviceIDObjects) == 0 || m.DeviceIDObjects[0].ID >= r.deviceIDObjectID
	}
	return false
}
