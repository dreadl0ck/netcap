package firewalltransport

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

func hasToken(h http.Header, key, want string) bool {
	for _, v := range h.Values(key) {
		for _, token := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(token), want) {
				return true
			}
		}
	}
	return false
}

func (h *Handler) webSocket(w http.ResponseWriter, r *http.Request) {
	if h.ownsWebSocketTransport {
		defer h.cfg.WebSocketTransport.(*http.Transport).CloseIdleConnections()
	}
	key, err := base64.StdEncoding.DecodeString(r.Header.Get("Sec-WebSocket-Key"))
	if r.ProtoMajor != 1 || r.ProtoMinor != 1 || r.Method != "GET" || !hasToken(r.Header, "Connection", "upgrade") || len(r.Header.Values("Upgrade")) != 1 || len(r.Header.Values("Sec-WebSocket-Version")) != 1 || r.Header.Get("Sec-WebSocket-Version") != "13" || len(r.Header.Values("Sec-WebSocket-Key")) != 1 || err != nil || len(key) != 16 || r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
		http.Error(w, "invalid WebSocket handshake", 400)
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	out := h.outbound(r, ctx)
	out.Body = nil
	out.Header.Del("Sec-WebSocket-Extensions")
	compression := h.cfg.WebSocketCompression && wsDeflateOffer(r.Header)
	if compression {
		out.Header.Set("Sec-WebSocket-Extensions", wsDeflateExtension)
	}
	timer := time.AfterFunc(h.cfg.MessageTimeout, cancel)
	resp, err := h.cfg.WebSocketTransport.RoundTrip(out)
	timer.Stop()
	if err != nil {
		http.Error(w, "WebSocket upstream failed", 502)
		return
	}
	defer resp.Body.Close()
	sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if resp.StatusCode != 101 || !validHeaders(resp.Header) || !hasToken(resp.Header, "Connection", "upgrade") || !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") || resp.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(sum[:]) || len(resp.Header.Values("Sec-WebSocket-Accept")) != 1 || !wsDeflateResponse(resp.Header, compression) {
		http.Error(w, "invalid WebSocket upstream handshake", 502)
		return
	}
	compression = compression && resp.Header.Get("Sec-WebSocket-Extensions") != ""
	selected := resp.Header.Get("Sec-WebSocket-Protocol")
	if len(resp.Header.Values("Sec-WebSocket-Protocol")) > 1 || selected != "" && !hasToken(r.Header, "Sec-WebSocket-Protocol", selected) {
		http.Error(w, "invalid WebSocket subprotocol", 502)
		return
	}
	up, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		http.Error(w, "upstream cannot upgrade", 502)
		return
	}
	e := event(r, "websocket", "response", nil, 101)
	e.Headers = resp.Header.Clone()
	if err := h.inspect(ctx, e); err != nil {
		http.Error(w, "response denied", inspectionStatus(err))
		return
	}
	down, rw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer down.Close()
	stop := context.AfterFunc(ctx, func() { _ = down.Close(); _ = up.Close() })
	defer stop()
	if err := down.SetWriteDeadline(time.Now().Add(h.cfg.MessageTimeout)); err != nil {
		return
	}
	if _, err := fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\n"); err != nil {
		return
	}
	if err := resp.Header.Write(rw); err != nil {
		return
	}
	if _, err := fmt.Fprint(rw, "\r\n"); err != nil {
		return
	}
	if err := rw.Flush(); err != nil {
		return
	}
	_ = down.SetWriteDeadline(time.Time{})
	done := make(chan error, 2)
	gate := func(phase string, src io.Reader, dst io.Writer, masked bool) {
		inspect := func(data []byte, opcode byte, index uint64) error {
			charge := int64(len(data))
			if h.cfg.ByteEvents {
				charge = 0
			}
			if !h.cfg.Budget.Acquire(charge) {
				return ErrBufferCapacity
			}
			defer h.cfg.Budget.Release(charge)
			e := h.messageEvent(r, "websocket", phase, data, 101)
			if phase == "response" {
				e.Headers = resp.Header.Clone()
			}
			e.Attributes["websocket.opcode"] = strconv.Itoa(int(opcode))
			e.Attributes["inspection.kind"] = "message"
			e.Attributes["message.index"] = strconv.FormatUint(index, 10)
			return h.inspect(ctx, e)
		}
		done <- gateWebSocketExtensions(ctx, src, dst, masked, h.cfg.MessageTimeout, cancel, inspect, h.cfg.Budget, compression)
	}
	go gate("request", rw.Reader, up, true)
	go gate("response", up, down, false)
	first := <-done
	secondDone := false
	if first == io.EOF {
		select {
		case <-done:
			secondDone = true
		case <-time.After(h.cfg.MessageTimeout):
		}
	}
	cancel()
	_ = down.Close()
	_ = up.Close()
	if !secondDone {
		<-done
	}
}

// Control frames are relayed immediately, including during fragmented messages.
// Data fragments are reassembled and emitted as one frame only after inspection.
func gateWebSocket(ctx context.Context, src io.Reader, dst io.Writer, masked bool, timeout time.Duration, abort context.CancelFunc, inspect func([]byte, byte, uint64) error) error {
	return gateWebSocketBudget(ctx, src, dst, masked, timeout, abort, inspect, nil)
}

func gateWebSocketBudget(ctx context.Context, src io.Reader, dst io.Writer, masked bool, timeout time.Duration, abort context.CancelFunc, inspect func([]byte, byte, uint64) error, budget *BufferBudget) error {
	return gateWebSocketExtensions(ctx, src, dst, masked, timeout, abort, inspect, budget, false)
}

func gateWebSocketExtensions(ctx context.Context, src io.Reader, dst io.Writer, masked bool, timeout time.Duration, abort context.CancelFunc, inspect func([]byte, byte, uint64) error, budget *BufferBudget, compression bool) error {
	var message []byte
	var current wsFrame
	var messageCharge int64
	defer func() {
		current.release()
		if budget != nil {
			budget.Release(messageCharge)
		}
	}()
	var opcode byte
	compressed := false
	var index uint64
	fragments := 0
	timer := time.AfterFunc(timeout, abort)
	defer func() { timer.Stop() }()
	renew := func() { timer.Stop(); timer = time.AfterFunc(timeout, abort) }
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		// The caller closes both connections on this timer, including writes blocked
		// by a peer that has stopped reading. Fragment/control traffic cannot renew it.
		current.release()
		frame, err := readWSFrameExtensions(src, masked, budget, compression)
		if err != nil {
			return err
		}
		current = frame
		if frame.opcode >= 8 {
			if frame.opcode == 8 && !validClose(frame.payload) {
				return ErrFraming
			}
			index++
			if err := inspect(frame.payload, frame.opcode, index); err != nil {
				return ErrDenied
			}
			if err := writeWSFrameBudget(dst, frame.opcode, frame.payload, masked, budget); err != nil {
				return err
			}
			if frame.opcode == 8 {
				return io.EOF
			}
			if opcode == 0 {
				renew()
			}
			continue
		}
		fragments++
		if fragments > 1024 {
			return ErrFraming
		}
		if frame.opcode == 0 {
			if opcode == 0 {
				return ErrFraming
			}
		} else {
			if opcode != 0 {
				return ErrFraming
			}
			opcode = frame.opcode
			compressed = frame.compressed
		}
		if len(message)+len(frame.payload) > MaxMessageBytes {
			return ErrFraming
		}
		message, err = appendWSMessage(message, frame.payload, budget)
		if err != nil {
			return err
		}
		messageCharge = int64(cap(message))
		if !frame.final {
			continue
		}
		if compressed {
			decoded, charge, err := inflateWS(message, budget)
			if err != nil {
				return err
			}
			if budget != nil {
				budget.Release(messageCharge)
			}
			message, messageCharge = decoded, charge
		}
		if opcode == 1 && !utf8.Valid(message) {
			return ErrFraming
		}
		index++
		if err := inspect(message, opcode, index); err != nil {
			return ErrDenied
		}
		if err := writeWSFrameBudget(dst, opcode, message, masked, budget); err != nil {
			return err
		}
		message = nil
		if budget != nil {
			budget.Release(messageCharge)
			messageCharge = 0
		}
		opcode = 0
		fragments = 0
		renew()
	}
}

// Growth reserves both backing arrays until the old contents have been copied.
func appendWSMessage(message, payload []byte, budget *BufferBudget) ([]byte, error) {
	required := len(message) + len(payload)
	if required > MaxMessageBytes {
		return message, ErrFraming
	}
	if required <= cap(message) {
		oldLen := len(message)
		message = message[:required]
		copy(message[oldLen:], payload)
		return message, nil
	}
	capacity := max(required, min(MaxMessageBytes, 2*cap(message)))
	if budget != nil && !budget.Acquire(int64(capacity)) {
		return message, ErrBufferCapacity
	}
	grown := make([]byte, required, capacity)
	copy(grown, message)
	copy(grown[len(message):], payload)
	if budget != nil {
		budget.Release(int64(cap(message)))
	}
	return grown, nil
}

type wsFrame struct {
	final      bool
	compressed bool
	opcode     byte
	payload    []byte
	budget     *BufferBudget
	charge     int64
}

func (f *wsFrame) release() {
	if f.budget != nil {
		f.budget.Release(f.charge)
		f.budget = nil
		f.charge = 0
	}
	f.payload = nil
}

func readWSFrame(r io.Reader, masked bool) (wsFrame, error) {
	return readWSFrameBudget(r, masked, nil)
}

func readWSFrameBudget(r io.Reader, masked bool, budget *BufferBudget) (_ wsFrame, err error) {
	return readWSFrameExtensions(r, masked, budget, false)
}

func readWSFrameExtensions(r io.Reader, masked bool, budget *BufferBudget, compression bool) (_ wsFrame, err error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return wsFrame{}, err
	}
	f := wsFrame{final: head[0]&128 != 0, opcode: head[0] & 15, compressed: head[0]&64 != 0}
	if head[0]&48 != 0 || f.compressed && (!compression || f.opcode != 1 && f.opcode != 2) || (head[1]&128 != 0) != masked || (f.opcode != 0 && f.opcode != 1 && f.opcode != 2 && f.opcode != 8 && f.opcode != 9 && f.opcode != 10) {
		return f, ErrFraming
	}
	n := uint64(head[1] & 127)
	if f.opcode >= 8 && (!f.final || n > 125) {
		return f, ErrFraming
	}
	switch n {
	case 126:
		var b [2]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return f, err
		}
		n = uint64(binary.BigEndian.Uint16(b[:]))
		if n < 126 {
			return f, ErrFraming
		}
	case 127:
		var b [8]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return f, err
		}
		n = binary.BigEndian.Uint64(b[:])
		if n < 65536 {
			return f, ErrFraming
		}
	}
	if n > MaxMessageBytes {
		return f, ErrFraming
	}
	if budget != nil {
		if !budget.Acquire(int64(n)) {
			return f, ErrBufferCapacity
		}
		f.budget = budget
		f.charge = int64(n)
		defer func() {
			if err != nil {
				f.release()
			}
		}()
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(r, mask[:]); err != nil {
			return f, err
		}
	}
	f.payload = make([]byte, int(n))
	if _, err := io.ReadFull(r, f.payload); err != nil {
		return f, err
	}
	if masked {
		for i := range f.payload {
			f.payload[i] ^= mask[i%4]
		}
	}
	return f, nil
}

func writeWSFrame(w io.Writer, opcode byte, payload []byte, masked bool) error {
	return writeWSFrameBudget(w, opcode, payload, masked, nil)
}

func writeWSFrameBudget(w io.Writer, opcode byte, payload []byte, masked bool, budget *BufferBudget) error {
	var head [14]byte
	head[0] = 128 | opcode
	n := 2
	switch {
	case len(payload) < 126:
		head[1] = byte(len(payload))
	case len(payload) <= 65535:
		head[1] = 126
		binary.BigEndian.PutUint16(head[2:], uint16(len(payload)))
		n = 4
	default:
		head[1] = 127
		binary.BigEndian.PutUint64(head[2:], uint64(len(payload)))
		n = 10
	}
	if masked {
		if budget != nil {
			if !budget.Acquire(int64(len(payload))) {
				return ErrBufferCapacity
			}
			defer budget.Release(int64(len(payload)))
		}
		head[1] |= 128
		if _, err := rand.Read(head[n : n+4]); err != nil {
			return err
		}
		data := make([]byte, len(payload))
		copy(data, payload)
		for i := range data {
			data[i] ^= head[n+i%4]
		}
		payload = data
		n += 4
	}
	if err := writeAll(w, head[:n]); err != nil {
		return err
	}
	return writeAll(w, payload)
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

func validClose(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	if len(b) == 1 {
		return false
	}
	code := binary.BigEndian.Uint16(b)
	return (code >= 1000 && code <= 1014 && code != 1004 && code != 1005 && code != 1006 || code >= 3000 && code <= 4999) && utf8.Valid(b[2:])
}
