package http

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/gogo/protobuf/proto"
)

func incrementalFixture(t *testing.T, budget *core.StateBudget) (*incrementalHTTP, *httpEvidenceWriter) {
	t.Helper()
	old, cfg, count := Decoder.Writer, config.Instance, Decoder.NumRecordsWritten
	t.Cleanup(func() { Decoder.Writer, config.Instance, Decoder.NumRecordsWritten = old, cfg, count })
	w := new(httpEvidenceWriter)
	Decoder.Writer, config.Instance = w, &config.Config{IncludePayloads: true}
	c := &core.ConversationInfo{Ident: "192.0.2.1:50000->192.0.2.2:80", CommunityID: "1:fixture", ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", ClientPort: 50000, ServerPort: 80}
	e := (&httpReader{}).NewIncremental(c, budget).(*incrementalHTTP)
	t.Cleanup(e.Abort)
	return e, w
}

func TestIncrementalHTTPKeepaliveSegmentationParity(t *testing.T) {
	request := "GET /one HTTP/1.1\r\nHost: fixture.test\r\n\r\nHEAD /head HTTP/1.1\r\nHost: fixture.test\r\n\r\nPOST /post HTTP/1.1\r\nHost: fixture.test\r\nTransfer-Encoding: chunked\r\n\r\n3;ext=yes\r\na=b\r\n0\r\nX-Trailer: yes\r\n\r\n"
	response := "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\noneHTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nHTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nX-Trailer: yes\r\n\r\n"
	want := captureHTTP(t, core.DataFragments{wireFragment(0, []byte(request), 10), wireFragment(1, []byte(response), 11)})
	if len(want) != 4 {
		t.Fatal("bad parity oracle", want)
	}
	for split := 1; split <= max(len(request), len(response)); split++ {
		t.Run(fmt.Sprint(split), func(t *testing.T) {
			budget, _ := core.NewStateBudget(1<<20, nil)
			e, writer := incrementalFixture(t, budget)
			for side, text := range []string{request, response} {
				for offset := 0; offset < len(text); offset += split {
					if err := e.Push(wireFragment(side, []byte(text[offset:min(offset+split, len(text))]), int64(10+side))); err != nil {
						t.Fatal(err)
					}
				}
			}
			if len(writer.records) != len(want) {
				t.Fatalf("completed records still await EOF: got %d want %d", len(writer.records), len(want))
			}
			for i, record := range writer.records {
				if !proto.Equal(record, want[i]) {
					t.Fatalf("split=%d record=%d\ngot %v\nwant %v", split, i, record, want[i])
				}
			}
			if e.used != 0 || budget.Health().RetainedBytes != 0 {
				t.Fatal("completed transactions retained parser bytes", e.used, budget.Health())
			}
			if err := e.Finish(core.StreamCompletion{}); err != nil {
				t.Fatal(err)
			}
			if err := e.Finish(core.StreamCompletion{}); err != nil || len(writer.records) != len(want) {
				t.Fatal("finalization replayed transactions", err)
			}
		})
	}
}

func TestIncrementalHTTPEOFCorruptionParity(t *testing.T) {
	for _, response := range []string{
		"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nNOT-HEX\r\nHTTP/1.1 299 Forged\r\n\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\nnot-a-header\r\n\r\nHTTP/1.1 299 Forged\r\n\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n+1\r\nx\r\n0\r\n\r\nHTTP/1.1 299 Forged\r\n\r\n",
		"HTTP/1.1 200 OK\r\n\r\nclose-delimited",
		"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 999\r\n\r\nHTTP/1.1 299 Forged\r\n\r\n",
	} {
		t.Run(response, func(t *testing.T) {
			req := wireFragment(0, []byte("GET /one HTTP/1.1\r\nHost: fixture.test\r\n\r\n"), 10)
			res := wireFragment(1, []byte(response), 11)
			want := captureHTTP(t, core.DataFragments{req, res})
			e, writer := incrementalFixture(t, nil)
			if err := e.Push(req); err != nil {
				t.Fatal(err)
			}
			if err := e.Push(res); err != nil {
				t.Fatal(err)
			}
			if len(writer.records) != 0 {
				t.Fatal("incomplete/ambiguous/close-delimited transaction emitted before EOF")
			}
			if err := e.Finish(core.StreamCompletion{ServerFIN: true}); err != nil {
				t.Fatal(err)
			}
			if len(writer.records) != len(want) {
				t.Fatal(writer.records, want)
			}
			for i := range want {
				if !proto.Equal(writer.records[i], want[i]) {
					t.Fatal(writer.records[i], want[i])
				}
			}
		})
	}
}

func TestIncrementalHTTPGapCannotJoinBodiesOrPairAcrossLoss(t *testing.T) {
	e, writer := incrementalFixture(t, nil)
	e.Push(wireFragment(0, []byte("POST /broken HTTP/1.1\r\nContent-Length: 100\r\n\r\nshort"), 10))
	gap := wireFragment(0, nil, 11)
	gap.SkippedBytes = 12
	if err := e.Push(gap); err != nil {
		t.Fatal(err)
	}
	e.Push(wireFragment(0, []byte("GET /after HTTP/1.1\r\nHost: fixture.test\r\n\r\n"), 12))
	e.Push(wireFragment(1, []byte("HTTP/1.1 404 Missing\r\nContent-Length: 0\r\n\r\n"), 13))
	if err := e.Finish(core.StreamCompletion{}); err != nil {
		t.Fatal(err)
	}
	for _, record := range writer.records {
		if record.ReassemblyStatus == "" {
			t.Fatal("loss became a clean transaction", record)
		}
		if record.URL == "/broken" && strings.Contains(string(record.RequestBody), "GET /after") {
			t.Fatal("joined a body across loss", record)
		}
		if record.Method != "" && record.StatusCode != 0 {
			t.Fatal("paired across capture loss", record)
		}
	}
	if len(writer.records) < 3 {
		t.Fatal("lost independent post-gap evidence", writer.records)
	}
}

func TestIncrementalHTTPSharedBudgetAbortReleasesState(t *testing.T) {
	budget, _ := core.NewStateBudget(4096, nil)
	e, _ := incrementalFixture(t, budget)
	err := e.Push(wireFragment(0, []byte("GET /one HTTP/1.1\r\nHost: fixture.test\r\n\r\n"), 10))
	if !errors.Is(err, core.ErrStreamStateBudget) {
		t.Fatal("budget failure did not propagate", err)
	}
	e.Abort()
	if h := budget.Health(); h.RetainedBytes != 0 || h.PeakBytes > h.LimitBytes || !h.Exceeded {
		t.Fatal(h)
	}
}

func TestIncrementalHTTPUpgradesStayCompletionOnly(t *testing.T) {
	e, writer := incrementalFixture(t, nil)
	e.Push(wireFragment(0, []byte("CONNECT fixture.test:443 HTTP/1.1\r\nHost: fixture.test\r\n\r\n"), 10))
	e.Push(wireFragment(1, []byte("HTTP/1.1 200 Connection Established\r\n\r\n"), 11))
	if len(writer.records) != 0 || !e.tunnel {
		t.Fatal("upgrade advertised incremental application support")
	}
	if err := e.Finish(core.StreamCompletion{}); err != nil || len(writer.records) != 1 {
		t.Fatal(err, writer.records)
	}
}

func TestIncrementalHTTPCloseDelimitedRequiresObservedEnd(t *testing.T) {
	for _, fin := range []bool{false, true} {
		t.Run(fmt.Sprint(fin), func(t *testing.T) {
			e, writer := incrementalFixture(t, nil)
			e.Push(wireFragment(0, []byte("GET /close HTTP/1.1\r\nHost: fixture.test\r\n\r\n"), 10))
			e.Push(wireFragment(1, []byte("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nbody"), 11))
			if len(writer.records) != 0 {
				t.Fatal("close-delimited body finalized while connection remained open")
			}
			if err := e.Finish(core.StreamCompletion{ServerFIN: fin, Reason: "capture-end"}); err != nil {
				t.Fatal(err)
			}
			if len(writer.records) != 1 {
				t.Fatal(writer.records)
			}
			qualified := strings.Contains(writer.records[0].ReassemblyStatus, "response-end-not-observed")
			if qualified == fin {
				t.Fatal("capture EOF was treated as an observed server FIN", writer.records[0])
			}
		})
	}
}

func TestIncrementalHTTPOwnsInputAndBorrowsDeferredTailOnce(t *testing.T) {
	e, writer := incrementalFixture(t, nil)
	request := []byte("POST /owned HTTP/1.1\r\nHost: fixture.test\r\nContent-Length: 1\r\n\r\nx")
	if err := e.Push(wireFragment(0, request, 10)); err != nil {
		t.Fatal(err)
	}
	for i := range request {
		request[i] = 0xff
	}
	e.Push(wireFragment(1, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 11))
	if len(writer.records) != 1 || writer.records[0].URL != "/owned" || string(writer.records[0].RequestBody) != "x" {
		t.Fatal("pooled input was retained", writer.records)
	}
	calls := 0
	e.SetTailObserver(func(c *core.ConversationInfo) {
		calls++
		var client strings.Builder
		for _, d := range c.ClientData {
			client.Write(d.Raw())
		}
		if strings.Contains(client.String(), "/owned") || !strings.Contains(client.String(), "CONNECT") {
			t.Fatal("tail replayed retired prefixes", client.String())
		}
	})
	e.Push(wireFragment(0, []byte("CONNECT fixture.test:443 HTTP/1.1\r\nHost: fixture.test\r\n\r\n"), 12))
	e.Push(wireFragment(1, []byte("HTTP/1.1 200 Connection Established\r\n\r\n"), 13))
	if err := e.Finish(core.StreamCompletion{}); err != nil {
		t.Fatal(err)
	}
	if err := e.Finish(core.StreamCompletion{}); err != nil || calls != 1 || len(writer.records) != 2 {
		t.Fatal("tail finalization repeated", err, calls, writer.records)
	}
}

func TestIncrementalHTTPCoalescedPipelineRetiresStorage(t *testing.T) {
	budget, _ := core.NewStateBudget(8<<20, nil)
	e, writer := incrementalFixture(t, budget)
	request := "GET /pipeline HTTP/1.1\r\nHost: fixture.test\r\n\r\n"
	if err := e.Push(wireFragment(0, []byte(strings.Repeat(request, 1000)), 10)); err != nil {
		t.Fatal(err)
	}
	if len(writer.records) != 0 {
		t.Fatal("unanswered pipelined requests emitted prematurely")
	}
	response := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	if err := e.Push(wireFragment(1, []byte(strings.Repeat(response, 1000)), 11)); err != nil {
		t.Fatal(err)
	}
	if len(writer.records) != 1000 || e.used != 0 || budget.Health().RetainedBytes != 0 {
		t.Fatal("coalesced input remained pinned after retirement", len(writer.records), e.used, budget.Health())
	}
	if err := e.Finish(core.StreamCompletion{}); err != nil || len(writer.records) != 1000 {
		t.Fatal("pipeline replayed at close", err)
	}
}

func TestIncrementalHTTPPendingRequestLimitIsExplicit(t *testing.T) {
	budget, _ := core.NewStateBudget(8<<20, nil)
	e, _ := incrementalFixture(t, budget)
	err := e.Push(wireFragment(0, []byte(strings.Repeat("GET / HTTP/1.1\r\nHost: fixture.test\r\n\r\n", 1025)), 10))
	if !errors.Is(err, core.ErrIncrementalLimit) {
		t.Fatal("pending request capacity was not explicit", err)
	}
	e.Abort()
	if budget.Health().RetainedBytes != 0 {
		t.Fatal("capacity rejection leaked parser ownership", budget.Health())
	}
}

func TestIncrementalHTTPContinueBeforeRequestBody(t *testing.T) {
	e, writer := incrementalFixture(t, nil)
	parts := []*core.StreamData{
		wireFragment(0, []byte("POST /continue HTTP/1.1\r\nHost: fixture.test\r\nContent-Length: 3\r\nExpect: 100-continue\r\n\r\n"), 10),
		wireFragment(1, []byte("HTTP/1.1 100 Continue\r\n\r\n"), 11),
		wireFragment(0, []byte("a=b"), 12),
		wireFragment(1, []byte("HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n"), 13),
	}
	for i, part := range parts {
		if err := e.Push(part); err != nil {
			t.Fatal(err)
		}
		if i < 3 && len(writer.records) != 0 {
			t.Fatal("interim response fabricated an unanswered request", writer.records)
		}
	}
	if len(writer.records) != 2 || writer.records[0].StatusCode != 100 || writer.records[1].StatusCode != 201 || e.used != 0 {
		t.Fatal(writer.records, e.used)
	}
	for _, row := range writer.records {
		if row.Method != "POST" || row.URL != "/continue" || row.ReassemblyStatus != "" {
			t.Fatal(row)
		}
	}
}

var _ core.IncrementalFactory = (*httpReader)(nil)
var _ core.IncrementalDecoder = (*incrementalHTTP)(nil)
