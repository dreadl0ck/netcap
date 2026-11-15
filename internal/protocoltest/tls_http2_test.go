package protocoltest

import (
	"bytes"
	"strings"
	"testing"

	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestTLSHTTP2ReadableHeadersAndBody(t *testing.T) {
	var client, server, block bytes.Buffer
	client.WriteString(http2.ClientPreface)
	encoder := hpack.NewEncoder(&block)
	for _, field := range []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "fixture.test"}, {Name: ":path", Value: "/readable"}} {
		if err := encoder.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	f := http2.NewFramer(&client, nil)
	if err := f.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes(), EndHeaders: true, EndStream: true}); err != nil {
		t.Fatal(err)
	}
	block.Reset()
	encoder = hpack.NewEncoder(&block)
	encoder.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	f = http2.NewFramer(&server, nil)
	if err := f.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes(), EndHeaders: true}); err != nil {
		t.Fatal(err)
	}
	if err := f.WriteData(1, true, []byte("synthetic readable result")); err != nil {
		t.Fatal(err)
	}
	messages, issues := decodeTLSHTTP2(client.Bytes(), server.Bytes())
	if len(issues) != 0 || len(messages) != 2 || messages[1].BodyText != "synthetic readable result" || messages[0].Headers[0] != [2]string{":method", "GET"} {
		t.Fatal(messages, issues)
	}
	_, issues = decodeTLSHTTP2(client.Bytes(), server.Bytes()[:server.Len()-1])
	if len(issues) == 0 {
		t.Fatal("truncated HTTP/2 data unqualified")
	}
}

func TestTLSStreamSelectionUsesCommunityIDAndRejectsAmbiguity(t *testing.T) {
	id := streamutils.CalcCommunityIDTCP("192.0.2.1", "198.51.100.1", 40000, 443)
	row := "7\t192.0.2.1\t\t40000\t198.51.100.1\t\t443\n"
	if index, err := selectTLSStream(row+row, id); err != nil || index != 7 {
		t.Fatal(index, err)
	}
	if _, err := selectTLSStream(row+strings.Replace(row, "7\t", "8\t", 1), id); err == nil {
		t.Fatal("ambiguous capture silently selected")
	}
	if _, err := selectTLSStream(row, streamutils.CalcCommunityIDTCP("192.0.2.2", "198.51.100.1", 40000, 443)); err == nil {
		t.Fatal("unobserved flow selected")
	}
}
