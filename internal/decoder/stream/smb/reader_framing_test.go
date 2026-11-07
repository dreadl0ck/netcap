package smb

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestSMBReaderConsumesNetBIOSControlBody(t *testing.T) {
	params := ntCreateParameters(len("file.txt"))
	msg := make([]byte, 33)
	copy(msg, "\xffSMB")
	msg[4], msg[32] = SMB1_COM_NT_CREATE_ANDX, 24
	msg = append(msg, params...)
	msg = binary.LittleEndian.AppendUint16(msg, uint16(len("file.txt")))
	msg = append(msg, "file.txt"...)
	wire := []byte{0x81, 0, 0, 4, 0, 0, 0, 0}
	wire = append(wire, 0, byte(len(msg)>>16), byte(len(msg)>>8), byte(len(msg)))
	wire = append(wire, msg...)
	r := bufio.NewReader(bytes.NewReader(wire))
	s := newTestSMBReader()
	if err := s.readSMBMessage(r, true); err != nil {
		t.Fatal(err)
	}
	if err := s.readSMBMessage(r, true); err != nil || s.filename != "file.txt" {
		t.Fatalf("filename=%q error=%v", s.filename, err)
	}
	if _, err := r.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatal("unconsumed frame bytes", err)
	}
}

func TestSMBReaderRejectsUnsafeFrameLengths(t *testing.T) {
	for _, wire := range [][]byte{
		{0, 0, 0, 3, 'S', 'M', 'B'},
		{0, 0x40, 0, 1},
		{0x81, 0, 0, 4, 0},
	} {
		if err := newTestSMBReader().readSMBMessage(bufio.NewReader(bytes.NewReader(wire)), true); err == nil {
			t.Fatalf("accepted unsafe frame %x", wire)
		}
	}
}
