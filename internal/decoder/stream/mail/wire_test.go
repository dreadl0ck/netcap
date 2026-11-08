package mail

import (
	"bufio"
	"bytes"
	"testing"
)

func TestDotMessagePreservesBinaryAndLineEndings(t *testing.T) {
	expected := []byte("Content-Type: application/octet-stream\r\n\r\n\x00\xff\r\n.leading\r\n")
	wire := bytes.ReplaceAll(expected, []byte("\r\n."), []byte("\r\n.."))
	wire = append(wire, []byte(".\r\nQUIT\r\n")...)
	reader := bufio.NewReader(bytes.NewReader(wire))
	body, release, err := ReadDotMessage(reader)
	defer release()
	if err != nil || !bytes.Equal(body, expected) {
		t.Fatalf("wire bytes changed: %x %v", body, err)
	}
	next, err := reader.ReadString('\n')
	if err != nil || next != "QUIT\r\n" {
		t.Fatalf("dot reader consumed next command: %q %v", next, err)
	}
}

func TestDotMessageTruncationIsNotCleanEOF(t *testing.T) {
	body, release, err := ReadDotMessage(bufio.NewReader(bytes.NewReader([]byte("Subject: owned\r\n\r\npartial"))))
	defer release()
	if err == nil || len(body) == 0 {
		t.Fatal("truncated message lost its qualification")
	}
}
