package http

import (
	"bufio"
	"bytes"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
)

func TestMalformedMetadataDoesNotLoseUnambiguousPairing(t *testing.T) {
	old, cfg, count := Decoder.Writer, config.Instance, Decoder.NumRecordsWritten
	t.Cleanup(func() { Decoder.Writer, config.Instance, Decoder.NumRecordsWritten = old, cfg, count })
	config.Instance = &config.Config{IncludePayloads: true}
	w := &httpEvidenceWriter{}
	Decoder.Writer = w
	request := []byte("GET /\xff\xfe HTTP/1.1\r\nHost: \xff\xfe.test\r\nUser-Agent: \x80\x81\x00bad\r\n\r\n")
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
	(&httpReader{conversation: &core.ConversationInfo{Data: core.DataFragments{&core.StreamData{RawData: request}, &core.StreamData{Dir: reassembly.TCPDirServerToClient, RawData: response}}}}).Decode()
	if len(w.records) != 1 || w.records[0].Method != "GET" || w.records[0].StatusCode != 200 {
		t.Fatal("unambiguous transaction was split", w.records)
	}
	record := w.records[0]
	if !strings.Contains(strings.Join(record.ParseQualifications, ","), "invalid-http-metadata-value") || !bytes.Equal(record.RawRequestLine, request[:bytes.Index(request, []byte("\r\n"))+2]) {
		t.Fatal("metadata qualification/raw line lost")
	}
	found := false
	for _, header := range record.RequestHeaders {
		if bytes.Equal(header.Name, []byte("User-Agent")) {
			found = bytes.Equal(header.Value, []byte(" \x80\x81\x00bad"))
		}
	}
	if !found {
		t.Fatal("exact malformed metadata evidence lost")
	}
}

func TestMalformedFramingStillPreventsPairing(t *testing.T) {
	for _, header := range []string{"Content-Length: 0\x00", "Transfer-Encoding: chunked\x00", "Bad Name: value", "Host: bad\x00host", "Content-Length: 1\r\nContent-Length: 2", "Transfer-Encoding: chunked\r\nContent-Length: 0"} {
		_, evidence, err := readEvidenceRequest(bufio.NewReader(strings.NewReader("POST / HTTP/1.1\r\n" + header + "\r\n\r\n")))
		if err == nil && !evidence.unsafe {
			t.Fatal("unsafe framing recovered", header)
		}
	}
}
