package mail

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/file"
	"testing"
)

func TestMIMEByteFaithfulMultipleAttachments(t *testing.T) {
	binary := []byte{0, 255, 13, 10, 128, 65}
	message := fmt.Sprintf("From: a@example.test\r\nTo: b@example.test\r\nContent-Type: multipart/mixed; boundary=outer\r\n\r\n--outer\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=first.bin\r\nContent-Transfer-Encoding: base64\r\n\r\n%s\r\n--outer\r\nContent-Type: multipart/mixed; boundary=inner\r\n\r\n--inner\r\nContent-Disposition: attachment; filename=second.bin\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n=00=FF=0D=0A=80A\r\n--inner--\r\n--outer--\r\n", base64.StdEncoding.EncodeToString(binary))
	_, parts, attachments, release, err := parseMIMEMessage([]byte(message))
	defer release()
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 2 || len(attachments) != 2 {
		t.Fatalf("parts %d attachments %d", len(parts), len(attachments))
	}
	for _, a := range attachments {
		if !bytes.Equal(a.data, binary) {
			t.Fatalf("attachment bytes changed: %x", a.data)
		}
	}
	if attachments[1].depth <= attachments[0].depth {
		t.Fatal("nested provenance lost")
	}
}

func TestMIMEBudgetAndMalformedTransfer(t *testing.T) {
	old := file.GetGlobalConfig()
	defer file.SetGlobalConfig(old)
	cfg := file.GetDefaultConfig()
	cfg.FileExtraction.SizeLimits.MaxFileSize = 8
	file.SetGlobalConfig(cfg)
	for _, body := range []string{"Content-Type: multipart/mixed\r\n\r\nmissing boundary", "Content-Transfer-Encoding: base64\r\n\r\n!!!!", "Content-Type: text/plain\r\n\r\n0123456789"} {
		_, _, _, release, err := parseMIMEMessage([]byte(body))
		release()
		if err == nil {
			t.Fatalf("malformed/over-budget input accepted: %s", body)
		}
	}
}
