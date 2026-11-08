package http

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/software"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/internal/webtech/testfixture"
	"github.com/gopacket/gopacket"
)

type deniedHTTP struct{ calls atomic.Int32 }

func (d *deniedHTTP) RoundTrip(*http.Request) (*http.Response, error) {
	d.calls.Add(1)
	return nil, fmt.Errorf("active HTTP forbidden")
}

func TestInstalledFourRuleCaptureInitOfflineAndPrivate(t *testing.T) {
	f, err := testfixture.Build()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "enrichment")
	if err = f.Install(root); err != nil {
		t.Fatal(err)
	}
	denied := &deniedHTTP{}
	transport := http.DefaultTransport
	http.DefaultTransport = denied
	t.Cleanup(func() { http.DefaultTransport = transport })
	state := software.InitializeWebtechWith(root, f.Trust, time.Unix(f.Now, 0))
	if state.State != "external" || state.Rules != 4 || state.SHA256 == "" {
		t.Fatal(state)
	}
	if err = os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	old, cfg, items, count := Decoder.Writer, config.Instance, software.Store.Items, Decoder.NumRecordsWritten
	t.Cleanup(func() {
		Decoder.Writer, config.Instance, software.Store.Items, Decoder.NumRecordsWritten = old, cfg, items, count
		software.InitializeWebtech()
	})
	config.Instance = &config.Config{}
	software.Store.Items = map[string]*software.AtomicSoftware{}
	body := "<!doctype html><meta name=generator content='Hugo 0.147.0'><meta name=generator content='Joomla! - CMS'><meta name=generator content='WordPress 6.8.3'><script src='http://origin.example/active-forbidden.js'></script>private-body-marker"
	wire := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\nX-Generator: Drupal 11 (https://www.drupal.org)\r\nSet-Cookie: session=private-cookie-marker\r\nLocation: http://origin.example/probe-forbidden\r\n\r\n%s", len(body), body)
	writer := &httpEvidenceWriter{}
	Decoder.Writer = writer
	c := &core.ConversationInfo{Ident: "synthetic-optional-flow", ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", Data: core.DataFragments{&core.StreamData{RawData: []byte("GET / HTTP/1.1\r\nHost: origin.example\r\n\r\n")}, &core.StreamData{Dir: reassembly.TCPDirServerToClient, RawData: []byte(wire)}}}
	(&httpReader{conversation: c}).Decode()
	if len(software.Store.Items) != 4 || len(writer.records) != 1 || len(writer.records[0].ResponseBody) != 0 {
		t.Fatal("optional capture not ready/private", len(software.Store.Items), writer.records)
	}
	for _, s := range software.Store.Items {
		if strings.Contains(fmt.Sprint(s.Software), "private-") || s.ObservedHost != "" || s.ConfidenceLevel != "low" || s.HasKnownVulnerabilities {
			t.Fatal("false attribution or retained private data", s.Software)
		}
	}
	if denied.calls.Load() != 0 {
		t.Fatal("active HTTP attempted", denied.calls.Load())
	}
}

func TestPassiveWebtechTransientCapture(t *testing.T) {
	old, cfg, items, count := Decoder.Writer, config.Instance, software.Store.Items, Decoder.NumRecordsWritten
	t.Cleanup(func() {
		Decoder.Writer, config.Instance, software.Store.Items, Decoder.NumRecordsWritten = old, cfg, items, count
	})
	config.Instance = &config.Config{}
	body := "<!doctype html><meta name=generator content='WordPress 6.8.3'><p>private-body-marker</p>"
	wire := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\nSet-Cookie: session=private-cookie-marker\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", len(body), body)
	for split := 1; split < len(wire); split++ {
		software.Store.Items = map[string]*software.AtomicSoftware{}
		writer := &httpEvidenceWriter{}
		Decoder.Writer = writer
		c := &core.ConversationInfo{Ident: "synthetic-flow", ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", Data: core.DataFragments{
			&core.StreamData{RawData: []byte("GET /?private-query HTTP/1.1\r\nHost: origin.example\r\n\r\n"), CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(10, 0)}},
			&core.StreamData{Dir: reassembly.TCPDirServerToClient, RawData: []byte(wire[:split]), CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(11, 0)}},
			&core.StreamData{Dir: reassembly.TCPDirServerToClient, RawData: []byte(wire[split:]), CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(12, 0)}},
		}}
		reader := &httpReader{conversation: c}
		reader.Decode()
		if len(writer.records) != 1 || len(writer.records[0].ResponseBody) != 0 || writer.records[0].ResContentLength != int32(len(body)) || writer.records[0].ResContentTypeDetected != "text/html; charset=utf-8" {
			t.Fatalf("split %d: %v", split, writer.records)
		}
		if len(software.Store.Items) != 1 {
			t.Fatalf("split %d: %v", split, software.Store.Items)
		}
		for _, s := range software.Store.Items {
			if s.Product != "WordPress" || s.ObservedHost != "" || s.ObservationRole != "origin" || s.ConfidenceLevel != "low" || s.HasKnownVulnerabilities || s.VulnerabilityAssessment != "advertised-origin-only" {
				t.Fatal(s.Software)
			}
			if strings.Contains(fmt.Sprint(s.Software), "private-") {
				t.Fatal("private HTTP data retained in Software")
			}
		}
		if len(reader.responses) != 1 {
			t.Fatal("missing response")
		}
		remaining := make([]byte, 1)
		if n, _ := reader.responses[0].response.Body.Read(remaining); n != 0 {
			t.Fatal("body retained without IncludePayloads")
		}
	}
}
