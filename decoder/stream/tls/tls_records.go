package tls

import (
	"encoding/binary"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/types"
)

// A writer-only decoder: TLS retains its single stream reader and certificate path.
var RecordDecoder = &decoder.AbstractDecoder{
	Name: "TLSRecord", Type: types.Type_NC_TLSRecord,
	Description: "Stream-framed TLS record headers and known-plaintext alerts (no record payloads)",
}

const maxTLSRecordBody = 16384 + 2048
const maxTLSHandshake = 64 * 1024

type tlsRecordFramer struct {
	reader                        *tlsReader
	dir                           reassembly.TCPFlowDirection
	emit                          func(*types.TLSRecord)
	header                        [5]byte
	headerBytes                   int
	prefix                        [6]byte
	prefixBytes                   int
	record                        *types.TLSRecord
	offset, index                 uint64
	stopped, encrypted, plaintext bool
	handshake                     []byte
	certificateLimit              bool
}

func (h *tlsReader) frameConversation() {
	write := func(r *types.TLSRecord) {
		if RecordDecoder.Writer == nil {
			return
		}
		if err := RecordDecoder.Writer.Write(r); err != nil {
			tlsLog.Error("writing TLS record", zap.Error(err))
		} else {
			atomic.AddInt64(&RecordDecoder.NumRecordsWritten, 1)
		}
	}
	client := &tlsRecordFramer{reader: h, dir: reassembly.TCPDirClientToServer, emit: write}
	server := &tlsRecordFramer{reader: h, dir: reassembly.TCPDirServerToClient, emit: write}
	feed := func(d *core.StreamData) {
		f := client
		if d.Direction() == reassembly.TCPDirServerToClient {
			f = server
		}
		timestamp := d.CaptureInfo().Timestamp
		if d.Context() != nil {
			timestamp = d.Context().GetCaptureInfo().Timestamp
		}
		if d.SkippedBytes != 0 {
			f.gap(d.SkippedBytes, timestamp.UnixNano())
		}
		f.feed(d.Raw(), timestamp.UnixNano())
	}
	c, s := h.conversation.ClientData, h.conversation.ServerData
	if c == nil && s == nil {
		for _, fragment := range h.conversation.Data {
			if d, ok := fragment.(*core.StreamData); ok {
				feed(d)
			}
		}
	} else {
		// Merge heads by capture time without ever reordering either TCP direction.
		for len(c) > 0 || len(s) > 0 {
			useClient := len(s) == 0
			if len(c) > 0 && len(s) > 0 {
				useClient = true
				if c[0].Context() != nil && s[0].Context() != nil {
					useClient = !s[0].Context().GetCaptureInfo().Timestamp.Before(c[0].Context().GetCaptureInfo().Timestamp)
				}
			}
			if useClient {
				if d, ok := c[0].(*core.StreamData); ok {
					feed(d)
				}
				c = c[1:]
			} else {
				if d, ok := s[0].(*core.StreamData); ok {
					feed(d)
				}
				s = s[1:]
			}
		}
	}
	client.eof()
	server.eof()
}

func (f *tlsRecordFramer) begin(timestamp int64) {
	c := f.reader.conversation
	r := &types.TLSRecord{Timestamp: timestamp, Flow: c.Ident, CommunityID: c.CommunityID,
		Direction: f.dir.String(), Index: f.index, Offset: f.offset,
		SrcIP: c.ClientIP, DstIP: c.ServerIP, SrcPort: c.ClientPort, DstPort: c.ServerPort}
	if f.dir == reassembly.TCPDirServerToClient {
		r.SrcIP, r.DstIP, r.SrcPort, r.DstPort = c.ServerIP, c.ClientIP, c.ServerPort, c.ClientPort
	}
	f.record = r
}

func (f *tlsRecordFramer) feed(data []byte, timestamp int64) {
	for len(data) > 0 && !f.stopped {
		if f.record == nil {
			f.begin(timestamp)
		}
		if f.headerBytes < 5 {
			n := copy(f.header[f.headerBytes:], data)
			f.headerBytes += n
			f.offset += uint64(n)
			data = data[n:]
			f.record.ContentType = uint32(f.header[0])
			if f.headerBytes >= 3 {
				f.record.RecordVersion = uint32(binary.BigEndian.Uint16(f.header[1:3]))
			}
			if f.headerBytes < 5 {
				continue
			}
			f.record.HeaderComplete = true
			f.record.Length = uint32(binary.BigEndian.Uint16(f.header[3:5]))
			if f.record.Length > maxTLSRecordBody || f.record.RecordVersion < 0x300 || f.record.RecordVersion > 0x303 {
				f.record.Incomplete = true
				f.finish("invalid_header")
				f.stopped = true
				f.handshake = nil
				return
			}
		}
		n := min(len(data), int(f.record.Length-f.record.ObservedLength))
		f.prefixBytes += copy(f.prefix[f.prefixBytes:], data[:n])
		if Decoder.Writer != nil && f.dir == reassembly.TCPDirServerToClient && f.record.ContentType == 22 && !f.encrypted && !f.certificateLimit {
			if len(f.handshake)+n <= maxTLSHandshake {
				f.handshake = append(f.handshake, data[:n]...)
			} else {
				f.handshake = nil
				f.certificateLimit = true
			}
		}
		f.record.ObservedLength += uint32(n)
		f.offset += uint64(n)
		data = data[n:]
		if f.record.ObservedLength != f.record.Length {
			continue
		}
		r := f.record
		status := "complete"
		switch r.ContentType {
		case 20, 23:
			// Includes TLS 1.3 compatibility CCS; conservative without negotiated keys.
			f.encrypted = true
			f.handshake = nil
		case 21:
			r.AlertState = "encrypted_or_unknown"
			if f.plaintext && !f.encrypted {
				r.AlertState = "malformed"
				if r.Length == 2 && (f.prefix[0] == 1 || f.prefix[0] == 2) {
					r.PlaintextAlert = true
					r.AlertState = "plaintext"
					r.AlertLevel, r.AlertDescription = uint32(f.prefix[0]), uint32(f.prefix[1])
				}
			}
		case 22:
			if !f.encrypted && r.Offset == 0 && f.prefixBytes == 6 &&
				(f.prefix[0] == 1 || f.prefix[0] == 2) && f.prefix[4] == 3 && f.prefix[5] <= 3 {
				messageLength := int(f.prefix[1])<<16 | int(f.prefix[2])<<8 | int(f.prefix[3])
				f.plaintext = messageLength >= 38 && messageLength+4 <= int(r.Length)
			}
			for len(f.handshake) >= 4 {
				length := int(f.handshake[1])<<16 | int(f.handshake[2])<<8 | int(f.handshake[3])
				if length+4 > maxTLSHandshake {
					f.handshake = nil
					f.certificateLimit = true
					break
				}
				if length+4 > len(f.handshake) {
					break
				}
				if f.handshake[0] == handshakeTypeCertificate {
					f.reader.parseCertificateMessage(f.handshake[4 : 4+length])
				}
				f.handshake = f.handshake[4+length:]
			}
		case 24:
		default:
			status = "unknown_type"
			f.encrypted = true
			f.handshake = nil
		}
		f.finish(status)
	}
}

func (f *tlsRecordFramer) finish(status string) {
	f.record.Status = status
	if f.record.ContentType == 21 && f.record.AlertState == "" {
		f.record.AlertState = "encrypted_or_unknown"
	}
	f.emit(f.record)
	f.index++
	f.record = nil
	f.headerBytes, f.prefixBytes = 0, 0
	f.header = [5]byte{}
	f.prefix = [6]byte{}
}

func (f *tlsRecordFramer) gap(skipped int, timestamp int64) {
	if f.stopped {
		return
	}
	if f.record == nil {
		f.begin(timestamp)
	}
	f.record.Incomplete, f.record.Loss = true, true
	f.record.SkippedBytes = int64(skipped)
	f.finish("gap")
	if skipped > 0 {
		f.offset += uint64(skipped)
	}
	// No speculative resynchronization inside ciphertext after loss.
	f.stopped = true
	f.handshake = nil
}

func (f *tlsRecordFramer) eof() {
	if f.record != nil {
		f.record.Incomplete = true
		f.finish("eof")
	}
}
