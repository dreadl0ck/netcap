package http

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type h2Fixture struct {
	t       testing.TB
	data    core.DataFragments
	wire    [2]bytes.Buffer
	hpack   [2]bytes.Buffer
	encoder [2]*hpack.Encoder
	framer  [2]*http2.Framer
	clock   int64
}

func newH2Fixture(t testing.TB) *h2Fixture {
	f := &h2Fixture{t: t, clock: 10}
	for side := range f.encoder {
		f.encoder[side] = hpack.NewEncoder(&f.hpack[side])
		f.framer[side] = http2.NewFramer(&f.wire[side], nil)
	}
	f.wire[0].WriteString(http2.ClientPreface)
	f.check(f.framer[0].WriteSettings())
	f.flush(0)
	f.check(f.framer[1].WriteSettings())
	f.flush(1)
	return f
}

func (f *h2Fixture) check(err error) {
	f.t.Helper()
	if err != nil {
		f.t.Fatal(err)
	}
}
func (f *h2Fixture) flush(side int) {
	f.data = append(f.data, wireFragment(side, bytes.Clone(f.wire[side].Bytes()), f.clock))
	f.wire[side].Reset()
	f.clock++
}

func (f *h2Fixture) block(side int, fields ...string) []byte {
	f.hpack[side].Reset()
	for i := 0; i < len(fields); i += 2 {
		f.check(f.encoder[side].WriteField(hpack.HeaderField{Name: fields[i], Value: fields[i+1]}))
	}
	return bytes.Clone(f.hpack[side].Bytes())
}

func (f *h2Fixture) headers(side int, id uint32, end bool, fields ...string) {
	f.check(f.framer[side].WriteHeaders(http2.HeadersFrameParam{StreamID: id, EndStream: end, EndHeaders: true, BlockFragment: f.block(side, fields...)}))
	f.flush(side)
}

func requestFields(path string) []string {
	return []string{":method", "GET", ":scheme", "http", ":authority", "fixture.test", ":path", path, "x-shared", "client-table-value"}
}

func streamRecords(records []*types.HTTP) map[uint32]*types.HTTP {
	byID := make(map[uint32]*types.HTTP)
	for _, r := range records {
		if r.HTTP2StreamID != 0 {
			byID[r.HTTP2StreamID] = r
		}
	}
	return byID
}

func TestH2PriorKnowledgeMultiplexHPACKContinuationTrailers(t *testing.T) {
	f := newH2Fixture(t)
	block := f.block(0, requestFields("/one")...)
	f.check(f.framer[0].WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndStream: true, BlockFragment: block[:2]}))
	f.flush(0)
	f.check(f.framer[0].WriteContinuation(1, true, block[2:]))
	f.flush(0)
	f.headers(0, 3, true, requestFields("/three")...)
	f.headers(1, 3, false, ":status", "201", "content-length", "5", "x-shared", "server-table-value")
	f.check(f.framer[1].WriteData(3, true, []byte("three")))
	f.flush(1)
	f.headers(1, 1, false, ":status", "200", "content-length", "3", "x-shared", "server-table-value")
	f.check(f.framer[1].WriteData(1, false, []byte("one")))
	f.flush(1)
	f.headers(1, 1, true, "x-checksum", "one-hash")
	if !Decoder.CanDecode(f.data[0].Raw(), nil) {
		t.Fatal("prior knowledge not selected")
	}
	for _, reverse := range []bool{false, true} {
		var data core.DataFragments
		for _, fragment := range f.data {
			original := fragment.(*core.StreamData)
			for i := range original.RawData {
				part := *original
				part.RawData = original.RawData[i : i+1]
				if reverse {
					part.Dir = !part.Dir
				}
				data = append(data, &part)
			}
		}
		records := captureHTTP(t, data)
		if len(records) != 2 || records[0].HTTP2StreamID != 3 || records[1].HTTP2StreamID != 1 {
			t.Fatal(records)
		}
		byID := streamRecords(records)
		for id, r := range byID {
			if r.ReassemblyStatus != "" || r.Proto != "HTTP/2.0" || r.Method != "GET" || r.Host != "fixture.test" || r.RequestHeader["X-Shared"] != "client-table-value" || r.ResponseHeader["X-Shared"] != "server-table-value" {
				t.Fatal(r)
			}
			if id == 1 && (r.URL != "/one" || string(r.ResponseBody) != "one" || r.StatusCode != 200 || r.Timestamp != time.Unix(12, 123).UnixNano() || len(r.ResponseTrailers) != 1 || string(r.ResponseTrailers[0].Value) != "one-hash") {
				t.Fatal(r)
			}
			if id == 3 && (r.URL != "/three" || string(r.ResponseBody) != "three" || r.StatusCode != 201) {
				t.Fatal(r)
			}
		}
	}
}

func TestH2NegotiatedUpgradeAndRejection(t *testing.T) {
	for _, accepted := range []bool{true, false} {
		f := newH2Fixture(t)
		f.headers(0, 3, true, requestFields("/after-upgrade")...)
		f.headers(1, 1, true, ":status", "204")
		f.headers(1, 3, true, ":status", "200", "content-length", "0")
		request := "GET /upgrade HTTP/1.1\r\nHost: fixture.test\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: \r\n\r\n"
		response := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"
		if !accepted {
			response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
		}
		f.data[0].(*core.StreamData).RawData = append([]byte(request), f.data[0].Raw()...)
		f.data[1].(*core.StreamData).RawData = append([]byte(response), f.data[1].Raw()...)
		records := captureHTTP(t, f.data)
		byID := streamRecords(records)
		if !accepted {
			if len(byID) != 0 {
				t.Fatal("decoded rejected upgrade", records)
			}
			continue
		}
		if len(records) != 3 || len(byID) != 2 || byID[1].URL != "/upgrade" || byID[1].StatusCode != 204 || byID[3].URL != "/after-upgrade" || byID[1].Proto != "HTTP/2.0" {
			t.Fatal(records)
		}
	}
}

func TestH2RejectedUpgradeResumesHTTP1(t *testing.T) {
	for _, status := range []string{"200 OK", "400 Bad Request"} {
		for _, informational := range []string{"", "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </asset>\r\n\r\n"} {
			for _, layout := range []string{"coalesced", "segmented", "bytewise"} {
				t.Run(status+"/info="+strconv.FormatBool(informational != "")+"/"+layout, func(t *testing.T) {
					request := "GET /before HTTP/1.1\r\nHost: fixture.test\r\n\r\n" +
						"GET /upgrade HTTP/1.1\r\nHost: fixture.test\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: \r\n\r\n"
					body := "GET /body-only HTTP/1.1\r\n\r\n"
					next := "POST /after HTTP/1.1\r\nHost: fixture.test\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
					response := "HTTP/1.1 204 No Content\r\n\r\n" + informational + "HTTP/1.1 " + status + "\r\nContent-Length: 0\r\n\r\n"
					data := core.DataFragments{
						wireFragment(0, []byte(request), 10),
						wireFragment(1, []byte(response), 11),
						wireFragment(0, []byte(next), 12),
						wireFragment(1, []byte("HTTP/1.1 201 Created\r\nContent-Length: 5\r\n\r\nreply"), 13),
					}
					records := captureHTTP(t, h2UpgradeLayout(data, layout))
					want := 3
					if informational != "" {
						want += 2
					}
					if len(records) != want {
						t.Fatalf("got %d records, want %d: %v", len(records), want, records)
					}
					for _, r := range records {
						if r.Proto != "HTTP/1.1" || r.HTTP2StreamID != 0 || r.ReassemblyStatus != "" {
							t.Fatal(r)
						}
						if r.StatusCode == 100 || r.StatusCode == 103 {
							if r.URL != "/upgrade" {
								t.Fatal("informational response paired with wrong request", r)
							}
						}
					}
					r := records[len(records)-1]
					if r.URL != "/after" || r.Method != "POST" || r.StatusCode != 201 || string(r.RequestBody) != body || string(r.ResponseBody) != "reply" {
						t.Fatal("lost HTTP/1 transaction after rejected upgrade", r)
					}
				})
			}
		}
	}
}

func h2UpgradeLayout(data core.DataFragments, layout string) core.DataFragments {
	if layout == "segmented" {
		return data
	}
	var out core.DataFragments
	if layout == "coalesced" {
		var wire [2][]byte
		for _, f := range data {
			side := 0
			if f.Direction() == reassembly.TCPDirServerToClient {
				side = 1
			}
			wire[side] = append(wire[side], f.Raw()...)
		}
		for side := range wire {
			out = append(out, wireFragment(side, wire[side], 10))
		}
		return out
	}
	for _, f := range data {
		for i := range f.Raw() {
			part := *f.(*core.StreamData)
			part.RawData = f.Raw()[i : i+1]
			out = append(out, &part)
		}
	}
	return out
}

func TestH2AcceptedUpgradeAfterRejection(t *testing.T) {
	for _, informational := range []string{"", "HTTP/1.1 103 Early Hints\r\n\r\n"} {
		for _, layout := range []string{"coalesced", "segmented", "bytewise"} {
			t.Run("info="+strconv.FormatBool(informational != "")+"/"+layout, func(t *testing.T) {
				f := newH2Fixture(t)
				f.headers(0, 3, true, requestFields("/after-upgrade")...)
				f.headers(1, 1, true, ":status", "204")
				f.headers(1, 3, true, ":status", "200", "content-length", "0")
				upgrade := " HTTP/1.1\r\nHost: fixture.test\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: \r\n\r\n"
				request := "GET /rejected" + upgrade + "GET /accepted" + upgrade
				response := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" + informational +
					"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"
				f.data[0].(*core.StreamData).RawData = append([]byte(request), f.data[0].Raw()...)
				f.data[1].(*core.StreamData).RawData = append([]byte(response), f.data[1].Raw()...)
				records := captureHTTP(t, h2UpgradeLayout(f.data, layout))
				want := 4
				if informational != "" {
					want++
				}
				byID := streamRecords(records)
				if len(records) != want || len(byID) != 2 || byID[1].URL != "/accepted" || byID[1].StatusCode != 204 || byID[3].URL != "/after-upgrade" || byID[3].StatusCode != 200 {
					t.Fatal(records)
				}
				for _, r := range records {
					if r.ReassemblyStatus != "" || (r.StatusCode == 103 && r.URL != "/accepted") {
						t.Fatal(r)
					}
				}
			})
		}
	}
}

func TestH2UpgradeInformationalResponseDoesNotResumeHTTP1(t *testing.T) {
	request := "GET /upgrade HTTP/1.1\r\nHost: fixture.test\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: \r\n\r\n" +
		"POST /pending HTTP/1.1\r\nHost: fixture.test\r\nContent-Length: 4\r\n\r\nbody"
	for _, layout := range []string{"coalesced", "segmented", "bytewise"} {
		t.Run(layout, func(t *testing.T) {
			records := captureHTTP(t, h2UpgradeLayout(core.DataFragments{
				wireFragment(0, []byte(request), 10),
				wireFragment(1, []byte("HTTP/1.1 103 Early Hints\r\n\r\n"), 11),
			}, layout))
			if len(records) == 0 {
				t.Fatal("lost upgrade evidence")
			}
			for _, r := range records {
				if r.URL != "/upgrade" || r.HTTP2StreamID != 0 {
					t.Fatal("informational response resolved pending upgrade", r)
				}
			}
		})
	}
}

func TestH2ResetEOFGapAndGoAway(t *testing.T) {
	for _, end := range []string{"eof", "reset", "gap", "discard", "goaway"} {
		t.Run(end, func(t *testing.T) {
			f := newH2Fixture(t)
			f.headers(0, 1, true, requestFields("/partial")...)
			f.headers(0, 3, true, requestFields("/complete")...)
			f.headers(1, 1, false, ":status", "200", "content-length", "7")
			f.check(f.framer[1].WriteData(1, false, []byte("part")))
			f.flush(1)
			f.headers(1, 3, true, ":status", "204")
			switch end {
			case "reset":
				f.check(f.framer[1].WriteRSTStream(1, http2.ErrCodeCancel))
				f.flush(1)
			case "goaway":
				f.check(f.framer[1].WriteGoAway(1, http2.ErrCodeNo, nil))
				f.flush(1)
			case "gap", "discard":
				f.check(f.framer[1].WriteData(1, true, []byte("ial")))
				f.flush(1)
				d := f.data[len(f.data)-1].(*core.StreamData)
				if end == "gap" {
					d.SkippedBytes = 3
				} else {
					d.DiscardedBytes = 3
				}
			}
			records := captureHTTP(t, f.data)
			byID := streamRecords(records)
			if len(byID) != 2 || byID[3].StatusCode != 204 || byID[3].ReassemblyStatus != "" || string(byID[1].ResponseBody) != "part" || !strings.Contains(byID[1].ReassemblyStatus, "h2-incomplete-direction-1") {
				t.Fatal(records)
			}
			if end == "reset" && !strings.Contains(byID[1].ReassemblyStatus, "h2-reset-8") {
				t.Fatal(records)
			}
			if (end == "gap" || end == "discard") && !strings.Contains(byID[1].ReassemblyStatus, "h2-capture-gap") {
				t.Fatal(records)
			}
		})
	}
}

func TestH2HostileFramingAndHeaderBounds(t *testing.T) {
	for _, test := range []string{"hpack", "continuation-interleave", "oversized-frame", "header-list", "header-table", "even-stream", "pseudo-header", "stream-limit"} {
		t.Run(test, func(t *testing.T) {
			f := newH2Fixture(t)
			switch test {
			case "hpack":
				f.check(f.framer[0].WriteHeaders(http2.HeadersFrameParam{StreamID: 1, EndHeaders: true, EndStream: true, BlockFragment: []byte{0xff, 0xff, 0xff, 0xff, 0x7f}}))
				f.flush(0)
			case "continuation-interleave":
				f.check(f.framer[0].WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: []byte{0x82}}))
				f.flush(0)
				f.check(f.framer[0].WriteData(1, true, []byte("GET /fake HTTP/1.1\r\n\r\n")))
				f.flush(0)
			case "oversized-frame":
				f.wire[0].Write([]byte{1, 0, 1, 0, 0, 0, 0, 0, 1})
				f.flush(0)
			case "header-list":
				fields := requestFields("/limit")
				for range maxHTTPHeaderCount {
					fields = append(fields, "x-repeated", "small compressed, large expanded")
				}
				f.headers(0, 1, true, fields...)
			case "header-table":
				f.encoder[0].SetMaxDynamicTableSizeLimit(h2MaxTable * 2)
				f.encoder[0].SetMaxDynamicTableSize(h2MaxTable * 2)
				f.headers(0, 1, true, requestFields("/limit")...)
			case "even-stream":
				f.headers(0, 2, true, requestFields("/bad")...)
			case "pseudo-header":
				f.headers(0, 1, true, "x-regular", "before-pseudo", ":method", "GET", ":method", "POST", ":path", "/bad", ":scheme", "http")
			case "stream-limit":
				for i := range h2MaxStreams + 1 {
					f.headers(0, uint32(2*i+1), true, requestFields("/limit")...)
				}
			}
			records := captureHTTP(t, f.data)
			if len(records) == 0 {
				t.Fatal("failure silently dropped")
			}
			qualified := false
			for _, r := range records {
				if r.ReassemblyStatus != "" {
					qualified = true
				}
				if r.URL == "/fake" || r.Proto != "HTTP/2.0" || r.StatusCode != 0 {
					t.Fatal(r)
				}
			}
			if !qualified {
				t.Fatal(records)
			}
		})
	}
}

func TestH2BodyLimitPreservesLengthAndNextStream(t *testing.T) {
	f := newH2Fixture(t)
	f.headers(0, 1, false, ":method", "POST", ":scheme", "http", ":authority", "fixture.test", ":path", "/large")
	for range h2MaxBody / 16384 {
		f.check(f.framer[0].WriteData(1, false, bytes.Repeat([]byte("x"), 16384)))
		f.flush(0)
	}
	f.check(f.framer[0].WriteData(1, true, []byte("!")))
	f.flush(0)
	f.headers(1, 1, true, ":status", "204")
	f.headers(0, 3, true, requestFields("/after-limit")...)
	f.headers(1, 3, true, ":status", "204")
	records := captureHTTP(t, f.data)
	byID := streamRecords(records)
	if len(records) != 2 || byID[1].ReqContentLength != h2MaxBody+1 || len(byID[1].RequestBody) != h2MaxBody || !strings.Contains(byID[1].ReassemblyStatus, "h2-body-limit") || byID[3].URL != "/after-limit" || byID[3].ReassemblyStatus != "" {
		t.Fatal("body limit or subsequent transaction failed")
	}
}

func TestH2BodylessResponsesAndInvalidLength(t *testing.T) {
	for _, tc := range []struct {
		method, status, length, body, issue string
	}{
		{"HEAD", "200", "100", "", ""},
		{"GET", "304", "100", "", ""},
		{"HEAD", "200", "1", "x", "h2-data-on-bodyless-response"},
		{"GET", "204", "1", "x", "h2-data-on-bodyless-response"},
		{"GET", "304", "1", "x", "h2-data-on-bodyless-response"},
		{"GET", "200", "+1", "x", "h2-invalid-content-length,h2-content-length-mismatch"},
	} {
		t.Run(tc.method+tc.status+tc.length+tc.body, func(t *testing.T) {
			f := newH2Fixture(t)
			f.headers(0, 1, true, ":method", tc.method, ":scheme", "http", ":authority", "fixture.test", ":path", "/bodyless")
			f.headers(1, 1, tc.body == "", ":status", tc.status, "content-length", tc.length)
			if tc.body != "" {
				f.check(f.framer[1].WriteData(1, true, []byte(tc.body)))
				f.flush(1)
			}
			records := captureHTTP(t, f.data)
			if len(records) != 1 || records[0].ReassemblyStatus != tc.issue || string(records[0].ResponseBody) != tc.body {
				t.Fatal(records)
			}
		})
	}
}

func TestH2InvalidContentLengthEvidence(t *testing.T) {
	for _, side := range []int{0, 1} {
		for _, value := range []string{"", "-1", "+1", " 1", "1, 1", "9223372036854775808"} {
			t.Run(strconv.Itoa(side)+"/"+value, func(t *testing.T) {
				f := newH2Fixture(t)
				request := requestFields("/invalid-length")
				response := []string{":status", "200"}
				if side == 0 {
					request = append(request, "content-length", value)
				} else {
					response = append(response, "content-length", value)
				}
				f.headers(0, 1, true, request...)
				f.headers(1, 1, true, response...)
				records := captureHTTP(t, f.data)
				if len(records) != 1 || records[0].URL != "/invalid-length" || records[0].StatusCode != 200 || !strings.Contains(records[0].ReassemblyStatus, "h2-invalid-content-length") {
					t.Fatalf("unqualified malformed length: %v", records)
				}
				fields := records[0].RequestHeaders
				if side == 1 {
					fields = records[0].ResponseHeaders
				}
				if fields[len(fields)-1] == nil || string(fields[len(fields)-1].Value) != value {
					t.Fatal("lost malformed content-length evidence")
				}
			})
		}
	}
}

func FuzzH2Frames(f *testing.F) {
	f.Add([]byte{0, 0, 0, 4, 0, 0, 0, 0, 0})
	f.Add([]byte{0, 0, 1, 1, 5, 0, 0, 0, 1, 0x82})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 128<<10 {
			t.Skip()
		}
		wire := append([]byte(http2.ClientPreface), []byte{0, 0, 0, 4, 0, 0, 0, 0, 0}...)
		wire = append(wire, data...)
		records := captureHTTP(t, core.DataFragments{wireFragment(0, wire, 10)})
		for _, r := range records {
			if r.Proto != "HTTP/2.0" {
				t.Fatal("escaped h2 parser")
			}
		}
	})
}

func TestH2UpgradeSettingsValidation(t *testing.T) {
	// A valid-looking upgrade with invalid SETTINGS must stay HTTP/1.
	for _, settings := range []string{"=", "AA", "////", strings.Repeat("A", 4096)} {
		wire := "GET / HTTP/1.1\r\nHost: test\r\nUpgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\nHTTP2-Settings: " + settings + "\r\n\r\n"
		records := captureHTTP(t, core.DataFragments{wireFragment(0, []byte(wire), 10)})
		if len(records) != 1 || records[0].Proto != "HTTP/1.1" {
			t.Fatal(records)
		}
	}
}
