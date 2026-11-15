package http

import (
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
)

func TestHTTPHeaderAcrossReaderBoundary(t *testing.T) {
	for _, size := range []int{16383, 16384, 60000} {
		request := "GET /large HTTP/1.1\r\nHost: fixture.test\r\nX-Fill: " + strings.Repeat("x", size) + "\r\n\r\n"
		records := captureHTTP(t, core.DataFragments{wireFragment(0, []byte(request), 10), wireFragment(1, []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), 11)})
		if len(records) != 1 || records[0].Method != "GET" || records[0].StatusCode != 200 || records[0].ReqContentLength != 0 || len(records[0].RequestHeader["X-Fill"]) != size {
			t.Fatalf("header size=%d: %v", size, records)
		}
	}
}
