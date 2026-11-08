package smb

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

type auditWriter struct {
	netio.AuditRecordWriter
	records []*types.SMB
}

func (w *auditWriter) Write(m proto.Message) error {
	w.records = append(w.records, proto.Clone(m).(*types.SMB))
	return nil
}

func auditCommand(command uint16, next uint32) []byte {
	m := make([]byte, 72)
	copy(m, SMB2Signature)
	binary.LittleEndian.PutUint16(m[4:], 64)
	binary.LittleEndian.PutUint16(m[12:], command)
	binary.LittleEndian.PutUint32(m[20:], next)
	binary.LittleEndian.PutUint32(m[36:], 7)
	binary.LittleEndian.PutUint64(m[40:], 99)
	return m
}
func TestSMB2AuditCompoundAndAsync(t *testing.T) {
	old, count := Decoder.Writer, Decoder.NumRecordsWritten
	t.Cleanup(func() { Decoder.Writer, Decoder.NumRecordsWritten = old, count })
	w := &auditWriter{}
	Decoder.Writer = w
	s := newTestSMBReader()
	s.timestamp = 123
	first, last := auditCommand(SMB2_LOGOFF, 72), auditCommand(SMB2_ECHO, 0)
	last[16] = SMB2_FLAGS_RELATED_OPERATIONS
	binary.LittleEndian.PutUint32(last[36:], 0xffffffff)
	binary.LittleEndian.PutUint64(last[40:], 0xffffffffffffffff)
	if err := s.parseSMB2Message(append(first, last...), true); err != nil {
		t.Fatal(err)
	}
	if len(w.records) != 2 || w.records[0].Action != "LOGOFF" || w.records[1].Action != "" || w.records[1].CommandName != "ECHO" || w.records[1].TreeID != 7 || w.records[1].SessionID != 99 || w.records[1].Timestamp != 123 {
		t.Fatalf("compound audit: %+v", w.records)
	}
	w.records = nil
	async := auditCommand(SMB2_ECHO, 0)
	async[16] = SMB2_FLAGS_ASYNC_COMMAND | SMB2_FLAGS_SERVER_TO_REDIR
	binary.LittleEndian.PutUint64(async[32:], 0xdeadbeef12345678)
	if err := s.parseSMB2Message(async, false); err != nil {
		t.Fatal(err)
	}
	if len(w.records) != 1 || w.records[0].TreeID != 0 || !w.records[0].IsResponse || w.records[0].SrcIP != s.conversation.ServerIP {
		t.Fatalf("async ID used as tree: %+v", w.records)
	}
}

func TestSMB2CompoundRejectsOutOfFrameOffsets(t *testing.T) {
	for _, next := range []uint32{1, 63, 65, 80, 0xffffffff} {
		if err := newTestSMBReader().parseSMB2Message(auditCommand(SMB2_ECHO, next), true); err == nil {
			t.Fatalf("accepted offset %d", next)
		}
	}
}

func TestSMBOpaqueTransformVisibility(t *testing.T) {
	old, count := Decoder.Writer, Decoder.NumRecordsWritten
	t.Cleanup(func() { Decoder.Writer, Decoder.NumRecordsWritten = old, count })
	for _, encrypted := range []bool{false, true} {
		body := make([]byte, 16)
		copy(body, "\xfcSMB")
		want := "opaque-compressed"
		if encrypted {
			body = make([]byte, 52)
			copy(body, "\xfdSMB")
			body[42] = 1
			body[44] = 42
			want = "opaque-encrypted"
		}
		wire := append([]byte{0, 0, 0, byte(len(body))}, body...)
		if !Decoder.CanDecode(nil, wire) {
			t.Fatal("opaque SMB not recognized")
		}
		w := &auditWriter{}
		Decoder.Writer = w
		s := newTestSMBReader()
		s.authStatus = "SUCCESS"
		s.filename = "stale"
		s.timestamp = 456
		if err := s.readSMBMessage(bufio.NewReader(bytes.NewReader(wire)), false); err != nil {
			t.Fatal(err)
		}
		if len(w.records) != 1 {
			t.Fatalf("opaque records: %d", len(w.records))
		}
		m := w.records[0]
		if m.OperationType != want || m.Command != -1 || m.Filename != "" || m.AuthStatus != "" || m.Timestamp != 456 || !m.IsResponse || m.Version != 3 {
			t.Fatalf("invented transform semantics: %+v", m)
		}
	}
}
