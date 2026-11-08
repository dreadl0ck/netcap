package http

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/internal/reassembly"
)

const incrementalHTTPBytes = 8 << 20
const incrementalHTTPHeader = 64 << 10

var errIncrementalHTTPLimit = core.ErrIncrementalLimit

// HTTP/1 framing is incremental; the existing evidence parser consumes each
// completed transaction exactly once. No connection prefix is decoded again.
type incrementalHTTP struct {
	conversation *core.ConversationInfo
	budget       *core.StateBudget
	used         int64
	pending      [2][]httpPending
	frames       [2]*httpFrame
	requests     []*httpFrame
	interim      []*httpFrame
	lost         bool
	closed       bool
	failed       bool
	tunnel       bool
	completed    uint64
	gapResets    uint64
	tailObserver func(*core.ConversationInfo)
	completion   core.StreamCompletion
	loss         [2]httpLoss
}

type httpLoss struct {
	known     int
	unknown   bool
	discarded int64
	reason    string
}

func (e *incrementalHTTP) observeLoss(side int, d *core.StreamData) error {
	loss := &e.loss[side]
	if d.SkippedBytes > 0 {
		if d.SkippedBytes > int(^uint(0)>>1)-loss.known {
			return fmt.Errorf("%w: HTTP/1 loss counter overflow", core.ErrIncrementalLimit)
		}
		loss.known += d.SkippedBytes
	} else if d.SkippedBytes < 0 {
		loss.unknown = true
	}
	if d.DiscardedBytes > 0 {
		if d.DiscardedBytes > int64(^uint64(0)>>1)-loss.discarded {
			return fmt.Errorf("%w: HTTP/1 discard counter overflow", core.ErrIncrementalLimit)
		}
		loss.discarded += d.DiscardedBytes
		if loss.reason == "" {
			loss.reason = strings.Clone(d.DiscardReason[:min(len(d.DiscardReason), 128)])
		} else if loss.reason != d.DiscardReason {
			loss.reason = "multiple-local-discard-causes"
		}
	}
	return nil
}

func (e *incrementalHTTP) lossFragments(side int) core.DataFragments {
	loss := e.loss[side]
	dir := reassembly.TCPDirClientToServer
	if side == 1 {
		dir = reassembly.TCPDirServerToClient
	}
	var fragments core.DataFragments
	if loss.known != 0 || loss.discarded != 0 {
		fragments = append(fragments, &core.StreamData{Dir: dir, SkippedBytes: loss.known, DiscardedBytes: loss.discarded, DiscardReason: loss.reason})
	}
	if loss.unknown {
		fragments = append(fragments, &core.StreamData{Dir: dir, SkippedBytes: -1})
	}
	return fragments
}

func (e *incrementalHTTP) brokenDirections() [2]bool {
	var broken [2]bool
	for side, loss := range e.loss {
		broken[side] = loss.known != 0 || loss.unknown || loss.discarded != 0
	}
	return broken
}

type httpPending struct {
	data   *core.StreamData
	charge int64
}

type httpFrame struct {
	parts        core.DataFragments
	header       []byte
	headerCap    int64
	charge       int64
	method       string
	status       int
	mode         string
	remaining    int64
	line         []byte
	complete     bool
	chunked      bool
	trailerBytes int
}

func ownedHTTPBytes(data []byte) []byte {
	out := make([]byte, len(data))
	copy(out, data)
	return out
}

func (*httpReader) NewIncremental(c *core.ConversationInfo, b *core.StateBudget) core.IncrementalDecoder {
	copy := *c
	copy.Data, copy.ClientData, copy.ServerData = nil, nil, nil
	return &incrementalHTTP{conversation: &copy, budget: b}
}

func (e *incrementalHTTP) reserve(n int64) error {
	if n > incrementalHTTPBytes-e.used {
		return fmt.Errorf("%w: %d bytes", errIncrementalHTTPLimit, incrementalHTTPBytes)
	}
	if err := e.budget.Reserve(n); err != nil {
		return err
	}
	e.used += n
	return nil
}

func (e *incrementalHTTP) release(n int64) { e.used -= n; e.budget.Release(n) }

func (e *incrementalHTTP) Push(d *core.StreamData) error {
	if e.closed || e.failed {
		return nil
	}
	side := 0
	if d.Dir == reassembly.TCPDirServerToClient {
		side = 1
	}
	if d.SkippedBytes != 0 || d.DiscardedBytes > 0 || d.TCPObservation != "" {
		if err := e.observeLoss(side, d); err != nil {
			return err
		}
		e.gapResets++
		if err := e.flushTail(true); err != nil {
			return err
		}
		e.lost = true
	}
	if len(d.RawData) == 0 {
		return nil
	}
	// An accepted CONNECT/101 changes protocols. Keep the bounded opaque tail
	// for final visibility rather than interpreting it as HTTP transactions.
	n := int64(len(d.RawData) + 512)
	if err := e.reserve(n); err != nil {
		e.failed = true
		return err
	}
	copy := *d
	copy.RawData = ownedHTTPBytes(d.RawData)
	copy.AssemblerContext = nil
	copy.CaptureInformation = d.CaptureInfo()
	copy.CaptureInformation.AncillaryData = nil
	copy.SkippedBytes, copy.DiscardedBytes, copy.DiscardReason = 0, 0, ""
	e.pending[side] = append(e.pending[side], httpPending{data: &copy, charge: n})
	if e.tunnel {
		return nil
	}
	for {
		progress := false
		for side := range 2 {
			for len(e.pending[side]) > 0 {
				if side == 1 && len(e.requests) == 0 && (e.frames[0] == nil || e.frames[0].mode == "") {
					break
				}
				n, err := e.consume(side)
				if err != nil {
					e.failed = true
					return err
				}
				if n == 0 {
					break
				}
				progress = true
				if e.tunnel {
					return nil
				}
			}
		}
		if !progress {
			return nil
		}
	}
}

func (e *incrementalHTTP) consume(side int) (int, error) {
	f := e.frames[side]
	if f == nil {
		if err := e.reserve(512); err != nil {
			return 0, err
		}
		f = &httpFrame{charge: 512}
		e.frames[side] = f
	}
	d := e.pending[side][0].data
	data := d.RawData
	n := 0
	for n < len(data) && !f.complete {
		switch f.mode {
		case "":
			if len(f.header) == incrementalHTTPHeader {
				return n, fmt.Errorf("%w: header exceeds %d bytes", errIncrementalHTTPLimit, incrementalHTTPHeader)
			}
			if len(f.header) == cap(f.header) {
				capacity := min(incrementalHTTPHeader, max(512, 2*cap(f.header)))
				if err := e.reserve(int64(capacity)); err != nil {
					return n, err
				}
				header := make([]byte, len(f.header), capacity)
				copy(header, f.header)
				e.release(f.headerCap)
				f.charge += int64(capacity) - f.headerCap
				f.headerCap, f.header = int64(capacity), header
			}
			f.header = append(f.header, data[n])
			n++
			if bytes.HasSuffix(f.header, []byte("\r\n\r\n")) || bytes.HasSuffix(f.header, []byte("\n\n")) {
				if err := e.frameHeader(f, side); err != nil {
					if errors.Is(err, core.ErrStreamStateBudget) || errors.Is(err, errIncrementalHTTPLimit) {
						return n, err
					}
					f.mode = "opaque"
				}
				e.release(f.headerCap)
				f.charge -= f.headerCap
				f.header, f.headerCap = nil, 0
			}
		case "fixed":
			count := min(int64(len(data)-n), f.remaining)
			n += int(count)
			f.remaining -= count
			f.complete = f.remaining == 0
		case "chunk-data":
			count := min(int64(len(data)-n), f.remaining)
			n += int(count)
			f.remaining -= count
			if f.remaining == 0 {
				f.mode = "chunk-end"
			}
		case "chunk-size", "chunk-end", "trailer":
			if f.mode == "trailer" {
				f.trailerBytes++
				if f.trailerBytes > incrementalHTTPHeader {
					return n, fmt.Errorf("%w: trailers exceed %d bytes", errIncrementalHTTPLimit, incrementalHTTPHeader)
				}
			}
			if len(f.line) >= 8192 {
				f.mode = "opaque"
				continue
			}
			if f.line == nil {
				if err := e.reserve(8192); err != nil {
					return n, err
				}
				f.charge += 8192
				f.line = make([]byte, 0, 8192)
			}
			f.line = append(f.line, data[n])
			n++
			if data[n-1] == '\n' {
				line := strings.TrimSuffix(strings.TrimSuffix(string(f.line), "\n"), "\r")
				switch f.mode {
				case "chunk-size":
					value, _, _ := strings.Cut(line, ";")
					size, err := strconv.ParseUint(strings.TrimSpace(value), 16, 63)
					if err != nil {
						f.mode = "opaque"
					} else if size == 0 {
						f.mode = "trailer"
					} else {
						f.mode, f.remaining = "chunk-data", int64(size)
					}
				case "chunk-end":
					if line != "" {
						f.mode = "opaque"
					} else {
						f.mode = "chunk-size"
					}
				case "trailer":
					f.complete = line == ""
				}
				f.line = f.line[:0]
			}
		default: // close-delimited or untrusted framing waits for finalization.
			n = len(data)
		}
	}
	if n == 0 {
		return 0, nil
	}
	charge := int64(n + 512)
	if err := e.reserve(charge); err != nil {
		return n, err
	}
	part := *d
	part.RawData = ownedHTTPBytes(data[:n])
	f.parts = append(f.parts, &part)
	f.charge += charge
	if n == len(data) {
		charge := e.pending[side][0].charge
		e.pending[side][0] = httpPending{}
		e.pending[side] = e.pending[side][1:]
		e.release(charge)
	} else {
		// Keep the original allocation charged until its final suffix is consumed.
		d.RawData = data[n:]
	}
	if f.complete {
		if f.chunked {
			if err := e.validateChunked(f, side); err != nil {
				if errors.Is(err, core.ErrStreamStateBudget) || errors.Is(err, errIncrementalHTTPLimit) {
					return n, err
				}
				f.complete, f.mode = false, "opaque"
				return n, nil
			}
		}
		e.frames[side] = nil
		if side == 0 {
			if len(e.requests) >= 1024 {
				return n, fmt.Errorf("%w: HTTP/1 exceeds 1024 pending requests", core.ErrIncrementalLimit)
			}
			e.requests = append(e.requests, f)
		} else if f.status < 200 && f.status != 101 {
			e.interim = append(e.interim, f)
		} else if len(e.requests) > 0 {
			req := e.requests[0]
			tunnel := f.status == 101 || req.method == methodCONNECT && f.status >= 200 && f.status < 300
			if tunnel {
				e.tunnel = true
				e.interim = append(e.interim, f)
				return n, nil
			}
			if err := e.emit(req, append(e.interim, f), false); err != nil {
				return n, err
			}
			e.completed++
			e.freeFrame(req)
			for _, response := range e.interim {
				e.freeFrame(response)
			}
			e.freeFrame(f)
			e.interim = nil
			e.requests[0] = nil
			e.requests = e.requests[1:]
			e.tunnel = tunnel
		} else {
			e.interim = append(e.interim, f)
		}
	}
	return n, nil
}

func (e *incrementalHTTP) frameHeader(f *httpFrame, side int) error {
	working := int64(8*len(f.header) + 4096)
	if err := e.reserve(working); err != nil {
		return err
	}
	defer e.release(working)
	r := bufio.NewReader(bytes.NewReader(f.header))
	var length int64
	var transfer []string
	if side == 0 {
		req, _, err := readEvidenceRequest(r)
		if err != nil {
			return err
		}
		f.method, length, transfer = strings.Clone(req.Method), req.ContentLength, req.TransferEncoding
		if req.Method == methodCONNECT || req.Header.Get("Upgrade") != "" {
			e.tunnel = true
		}
	} else {
		method := ""
		if len(e.requests) > 0 {
			method = e.requests[0].method
		} else if e.frames[0] != nil {
			method = e.frames[0].method
		}
		res, _, err := readEvidenceResponse(r, &http.Request{Method: method})
		if err != nil {
			return err
		}
		f.status, length, transfer = res.StatusCode, res.ContentLength, res.TransferEncoding
		if method == methodHEAD || res.StatusCode < 200 || res.StatusCode == 204 || res.StatusCode == 304 || method == methodCONNECT && res.StatusCode >= 200 && res.StatusCode < 300 {
			length, transfer = 0, nil
		}
	}
	if len(transfer) > 0 {
		f.mode = "chunk-size"
		f.chunked = true
	} else if length < 0 && side == 1 {
		f.mode = "close"
	} else {
		f.mode, f.remaining = "fixed", max(0, length)
		f.complete = f.remaining == 0
	}
	return nil
}

// The evidence parser is authoritative for trailer syntax and chunk overflow.
// Validation traverses this message once, without extraction or record writes;
// corrupt boundaries remain opaque until finalization and cannot frame a suffix.
func (e *incrementalHTTP) validateChunked(f *httpFrame, side int) error {
	var wire int64
	for _, part := range f.parts {
		wire += int64(len(part.Raw()))
	}
	working := int64(64<<10) + 8*min(wire, 2*incrementalHTTPHeader)
	if err := e.reserve(working); err != nil {
		return err
	}
	defer e.release(working)
	r, _ := streamutils.FragmentReader(f.parts, side == 1)
	var body io.ReadCloser
	if side == 0 {
		request, _, err := readEvidenceRequest(r)
		if err != nil {
			return err
		}
		body = request.Body
	} else {
		method := ""
		if len(e.requests) > 0 {
			method = e.requests[0].method
		}
		response, _, err := readEvidenceResponse(r, &http.Request{Method: method})
		if err != nil {
			return err
		}
		body = response.Body
	}
	_, err := io.Copy(io.Discard, body)
	_ = body.Close()
	return err
}

func (e *incrementalHTTP) freeFrame(f *httpFrame) {
	if f != nil {
		e.release(f.charge)
		*f = httpFrame{}
	}
}

func (e *incrementalHTTP) emit(req *httpFrame, responses []*httpFrame, gap bool) error {
	c := *e.conversation
	if req != nil {
		c.ClientData = req.parts
	}
	for _, r := range responses {
		if r != nil {
			c.ServerData = append(c.ServerData, r.parts...)
		}
	}
	if gap || e.lost {
		c.ClientData = append(e.lossFragments(0), c.ClientData...)
		c.ServerData = append(e.lossFragments(1), c.ServerData...)
	}
	working := int64(4096)
	for _, d := range c.ClientData {
		working += 3 * int64(len(d.Raw()))
	}
	for _, d := range c.ServerData {
		working += 3 * int64(len(d.Raw()))
	}
	if err := e.reserve(working); err != nil {
		return err
	}
	defer e.release(working)
	reader := &httpReader{conversation: &c, captureLoss: gap || e.lost, directionBroken: e.brokenDirections()}
	reader.Decode()
	return reader.writeError
}

func (e *incrementalHTTP) flushTail(gap bool) error {
	// Outstanding requests/interims/partial directions are decoded only here.
	// A real gap is preserved at the boundary; a parser never joins its sides.
	c := *e.conversation
	for _, req := range e.requests {
		c.ClientData = append(c.ClientData, req.parts...)
	}
	if e.frames[0] != nil {
		c.ClientData = append(c.ClientData, e.frames[0].parts...)
	}
	for _, res := range e.interim {
		c.ServerData = append(c.ServerData, res.parts...)
	}
	if e.frames[1] != nil {
		c.ServerData = append(c.ServerData, e.frames[1].parts...)
	}
	for side := range 2 {
		for _, pending := range e.pending[side] {
			d := pending.data
			if side == 0 {
				c.ClientData = append(c.ClientData, d)
			} else {
				c.ServerData = append(c.ServerData, d)
			}
		}
	}
	if gap || e.lost {
		c.ClientData = append(c.ClientData, e.lossFragments(0)...)
		c.ServerData = append(c.ServerData, e.lossFragments(1)...)
	}
	if len(c.ClientData)+len(c.ServerData) > 0 {
		working := e.used*3 + 4096
		if err := e.reserve(working); err != nil {
			return err
		}
		reader := &httpReader{conversation: &c, unobservedResponseEnd: !e.completion.ServerFIN, captureLoss: gap || e.lost, directionBroken: e.brokenDirections()}
		reader.Decode()
		if e.tunnel && e.tailObserver != nil {
			e.tailObserver(&c)
		}
		e.release(working)
		if reader.writeError != nil {
			return reader.writeError
		}
	}
	e.clear()
	return nil
}

func (e *incrementalHTTP) clear() {
	e.pending = [2][]httpPending{}
	e.frames = [2]*httpFrame{}
	e.requests, e.interim = nil, nil
	e.release(e.used)
}

func (e *incrementalHTTP) Finish(completion core.StreamCompletion) error {
	if e.closed {
		return nil
	}
	e.closed = true
	e.completion = completion
	defer e.clear()
	if e.failed {
		return nil
	}
	return e.flushTail(false)
}

func (e *incrementalHTTP) Abort() { e.closed = true; e.clear() }

func (e *incrementalHTTP) SetTailObserver(observer func(*core.ConversationInfo)) {
	e.tailObserver = observer
}

func (e *incrementalHTTP) IncrementalReport() core.IncrementalReport {
	r := core.IncrementalReport{Protocol: "HTTP/1", CompletedTransactions: e.completed, GapResets: e.gapResets}
	if e.tunnel {
		r.DeferredTail = "CONNECT/Upgrade/101 tail is completion-only under the same parser budget"
	}
	return r
}
