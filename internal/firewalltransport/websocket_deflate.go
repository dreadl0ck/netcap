package firewalltransport

import (
	"compress/flate"
	"io"
	"net/http"
	"strings"
)

const wsDeflateExtension = "permessage-deflate; server_no_context_takeover; client_no_context_takeover"

const wsDeflateTail = "\x00\x00\xff\xff\x01\x00\x00\xff\xff"

// ReadByte prevents flate from buffering past the stream terminator.
type wsDeflateInput struct {
	wire []byte
	pos  int
}

func (r *wsDeflateInput) ReadByte() (byte, error) {
	if r.pos >= len(r.wire)+len(wsDeflateTail) {
		return 0, io.EOF
	}
	i := r.pos
	r.pos++
	if i < len(r.wire) {
		return r.wire[i], nil
	}
	return wsDeflateTail[i-len(r.wire)], nil
}
func (r *wsDeflateInput) Read(b []byte) (int, error) {
	n := 0
	for n < len(b) {
		v, e := r.ReadByte()
		if e != nil {
			return n, e
		}
		b[n] = v
		n++
	}
	return n, nil
}

func wsDeflateOffer(h http.Header) bool {
	for _, line := range h.Values("Sec-WebSocket-Extensions") {
		for _, offer := range strings.Split(line, ",") {
			parts := strings.Split(offer, ";")
			if strings.TrimSpace(parts[0]) != "permessage-deflate" {
				continue
			}
			seen := map[string]bool{}
			valid := true
			for _, part := range parts[1:] {
				p := strings.TrimSpace(part)
				if seen[p] {
					valid = false
				}
				seen[p] = true
				switch p {
				case "server_no_context_takeover", "client_no_context_takeover", "client_max_window_bits":
				default:
					valid = false
				}
			}
			if valid {
				return true
			}
		}
	}
	return false
}

func wsDeflateResponse(h http.Header, offered bool) bool {
	values := h.Values("Sec-WebSocket-Extensions")
	if len(values) == 0 {
		return true
	}
	if !offered || len(values) != 1 {
		return false
	}
	p := strings.Split(values[0], ";")
	if len(p) != 3 || strings.TrimSpace(p[0]) != "permessage-deflate" {
		return false
	}
	a, b := strings.TrimSpace(p[1]), strings.TrimSpace(p[2])
	return a == "server_no_context_takeover" && b == "client_no_context_takeover" || b == "server_no_context_takeover" && a == "client_no_context_takeover"
}

// Each message has its own inflater and 32 KiB dictionary; no history survives.
// The reservation covers output plus the inflater's fixed tables/window.
func inflateWS(wire []byte, budget *BufferBudget) ([]byte, int64, error) {
	const overhead = 128 << 10
	charge := int64(MaxMessageBytes + 1 + overhead)
	if budget != nil && !budget.Acquire(charge) {
		return nil, 0, ErrBufferCapacity
	}
	success := false
	defer func() {
		if !success && budget != nil {
			budget.Release(charge)
		}
	}()
	// RFC 7692 removes the sync-flush marker; the final empty block terminates
	// the standalone stream so truncated or trailing streams cannot pass.
	r := &wsDeflateInput{wire: wire}
	z := flate.NewReader(r)
	defer z.Close()
	b := make([]byte, MaxMessageBytes+1)
	n, err := io.ReadFull(z, b)
	if n > MaxMessageBytes || err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, 0, ErrFraming
	}
	// ReadFull returns ErrUnexpectedEOF only when the inflater reached clean EOF
	// after some output; a DEFLATE truncation also does, so explicitly test EOF.
	var extra [1]byte
	if _, err = z.Read(extra[:]); err != io.EOF || r.pos != len(wire)+len(wsDeflateTail) {
		return nil, 0, ErrFraming
	}
	success = true
	return b[:n], charge, nil
}
