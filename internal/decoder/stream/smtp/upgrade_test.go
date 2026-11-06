package smtp

import (
	"bufio"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"go.uber.org/zap"
	"io"
	"strings"
	"testing"
)

func TestSMTPUpgradeBoundaryAndAUTHCommand(t *testing.T) {
	old := smtpLog
	smtpLog = zap.NewNop()
	t.Cleanup(func() { smtpLog = old })
	r := &smtpReader{conversation: &core.ConversationInfo{}}
	line := func(s string) *bufio.Reader { return bufio.NewReader(strings.NewReader(s + "\r\n")) }
	_ = r.readRequest(line("AUTH LOGIN"))
	if len(r.smtpRequests) != 1 || r.smtpRequests[0].Command != "AUTH" {
		t.Fatal("AUTH command treated as message data")
	}
	_ = r.readRequest(line("STARTTLS"))
	_ = r.readResponse(line("220 ready to start TLS"))
	if !r.encrypted {
		t.Fatal("SMTP upgrade ignored")
	}
	if err := r.readRequest(line("\x16\x03\x01 fake")); err != io.EOF {
		t.Fatal("TLS parsed as SMTP")
	}
}
