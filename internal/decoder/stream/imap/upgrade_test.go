package imap

import (
	"bufio"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/netio"
	"io"
	"strings"
	"testing"
)

func TestTaggedSTARTTLSBoundary(t *testing.T) {
	old := Decoder.Writer
	Decoder.Writer = netio.NewAuditRecordWriter(&netio.WriterConfig{Null: true})
	t.Cleanup(func() { Decoder.Writer = old })
	r := &imapReader{conversation: &core.ConversationInfo{}}
	line := func(s string) *bufio.Reader { return bufio.NewReader(strings.NewReader(s + "\r\n")) }
	if err := r.readClient(line("A1 STARTTLS"), nil); err != nil {
		t.Fatal(err)
	}
	_ = r.readServer(line("* OK STARTTLS is supported"), nil)
	if r.isEncrypted {
		t.Fatal("untagged text accepted as upgrade")
	}
	_ = r.readServer(line("A2 OK unrelated"), nil)
	if r.isEncrypted {
		t.Fatal("wrong tag accepted")
	}
	_ = r.readServer(line("A1 OK begin TLS"), nil)
	if !r.isEncrypted || !r.startTLSSuccess {
		t.Fatal("tagged success ignored")
	}
	if err := r.readClient(line("\x16\x03\x01 garbage"), nil); err != io.EOF {
		t.Fatal("ciphertext parsed", err)
	}
	if err := r.readServer(line("certificate text"), nil); err != io.EOF {
		t.Fatal("ciphertext parsed", err)
	}
}
