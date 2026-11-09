package http

import (
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/file"
)

type transportExtractor struct {
	HTTPFileExtractor
	bodies []string
}

func (e *transportExtractor) ExtractFile(_ *core.ConversationInfo, body []byte, _ file.FileMetadata) error {
	e.bodies = append(e.bodies, string(body))
	return nil
}

func TestHTTPTransportBoundary(t *testing.T) {
	for _, reason := range []string{"after-rst", "after-fin"} {
		t.Run(reason, func(t *testing.T) {
			pre := wireFragment(0, []byte("GET /fabricated"), 1)
			post := wireFragment(0, []byte(" HTTP/1.1\r\nHost: test\r\n\r\nPOST /observed HTTP/1.1\r\nHost: test\r\nContent-Length: 4\r\n\r\nDATA"), 2)
			post.TCPObservation = reason
			response := wireFragment(1, []byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nBODY"), 3)
			response.TCPObservation = reason
			records := captureHTTP(t, core.DataFragments{pre, post, response})
			requestSeen, responseSeen := false, false
			for _, r := range records {
				if r.URL == "/fabricated" || r.Method != "" && r.StatusCode != 0 {
					t.Fatalf("fabricated framing or ordinary pairing: %v", r)
				}
				if !strings.Contains(r.ReassemblyStatus, reason+"; endpoint delivery unconfirmed") {
					t.Fatalf("unqualified observation: %v", r)
				}
				requestSeen = requestSeen || r.URL == "/observed"
				responseSeen = responseSeen || r.StatusCode == 200
			}
			if !requestSeen || !responseSeen {
				t.Fatalf("lost standalone observations: %v", records)
			}
			pre = wireFragment(0, []byte("GET /preclose HTTP/1.1\r\nHost: test\r\n\r\n"), 1)
			records = captureHTTP(t, core.DataFragments{pre, response})
			if len(records) != 2 {
				t.Fatalf("paired across close: %v", records)
			}
			for _, r := range records {
				if r.Method != "" && r.StatusCode != 0 {
					t.Fatalf("ordinary pairing across close: %v", r)
				}
			}
		})
	}
}

func TestHTTPPostClosePreservesFramedArtifactEvidence(t *testing.T) {
	oldWriter, oldConfig, oldCount := Decoder.Writer, config.Instance, Decoder.NumRecordsWritten
	oldExtractor, ok := file.GetExtractor("HTTP")
	if !ok {
		oldExtractor = &HTTPFileExtractor{}
	}
	t.Cleanup(func() {
		Decoder.Writer, config.Instance, Decoder.NumRecordsWritten = oldWriter, oldConfig, oldCount
		file.RegisterExtractor(oldExtractor)
	})
	e := &transportExtractor{}
	file.RegisterExtractor(e)
	Decoder.Writer = &httpEvidenceWriter{}
	config.Instance = &config.Config{FileStorage: t.TempDir(), IncludePayloads: true, WriteIncomplete: true}
	for _, reason := range []string{"", "after-fin", "after-rst"} {
		request := wireFragment(0, []byte("POST /file HTTP/1.1\r\nHost: test\r\nContent-Length: 4\r\n\r\nDATA"), 1)
		response := wireFragment(1, []byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nBODY"), 2)
		request.TCPObservation, response.TCPObservation = reason, reason
		(&httpReader{conversation: &core.ConversationInfo{Data: core.DataFragments{request, response}}}).Decode()
	}
	if strings.Join(e.bodies, ",") != "DATA,BODY,DATA,BODY,DATA,BODY" {
		t.Fatalf("extracted bodies = %q", e.bodies)
	}
}

func TestHTTPQualifiedBodyRecoveryRequiresPreCloseHeader(t *testing.T) {
	oldWriter, oldConfig := Decoder.Writer, config.Instance
	oldExtractor, _ := file.GetExtractor("HTTP")
	t.Cleanup(func() { Decoder.Writer, config.Instance = oldWriter, oldConfig; file.RegisterExtractor(oldExtractor) })
	config.Instance = &config.Config{FileStorage: t.TempDir(), IncludePayloads: true}
	for _, headerComplete := range []bool{false, true} {
		e := &transportExtractor{}
		file.RegisterExtractor(e)
		writer := &httpEvidenceWriter{}
		Decoder.Writer = writer
		request := wireFragment(0, []byte("GET /file HTTP/1.1\r\nHost: test\r\n\r\n"), 1)
		prefix, tail := "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nDA", "TA"
		if !headerComplete {
			prefix, tail = "HTTP/1.1 200 OK\r\nContent-Len", "gth: 4\r\n\r\nDATA"
		}
		first := wireFragment(1, []byte(prefix), 2)
		last := wireFragment(1, []byte(tail), 3)
		last.TCPObservation = "after-fin"
		(&httpReader{conversation: &core.ConversationInfo{Data: core.DataFragments{request, first, last}}}).Decode()
		if headerComplete && strings.Join(e.bodies, ",") != "DATA" {
			t.Fatalf("qualified body lost: %q", e.bodies)
		}
		if !headerComplete && len(e.bodies) != 0 {
			t.Fatal("header reconstructed across close")
		}
	}
}
