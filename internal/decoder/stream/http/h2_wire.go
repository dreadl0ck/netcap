package http

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"golang.org/x/net/http2"
)

const (
	h2MaxFrame        = 64 << 10
	h2MaxTable        = 16 << 10
	h2MaxStreams      = 128
	h2MaxTransactions = 4096
	h2MaxFrames       = 100000
	h2MaxBody         = 1 << 20
	h2MaxBodies       = 8 << 20
	h2MaxHeaders      = 2 << 20
)

var errH2Gap = errors.New("HTTP/2 capture gap")

// Read directly from retained fragments; never concatenate the conversation or
// cross a loss marker. Frame payload allocation is bounded by the Framer.
type h2Wire struct {
	fragments            core.DataFragments
	index, offset        int
	seen, initialUnknown bool
}

func (w *h2Wire) advance() error {
	for w.index < len(w.fragments) {
		f := w.fragments[w.index]
		if w.offset == 0 {
			if d, ok := f.(*core.StreamData); ok {
				if d.DiscardedBytes > 0 || d.SkippedBytes != 0 && (d.SkippedBytes != -1 || w.seen) {
					return errH2Gap
				}
				if d.SkippedBytes == -1 {
					w.initialUnknown = true
				}
			}
		}
		if w.offset < len(f.Raw()) {
			return nil
		}
		w.index++
		w.offset = 0
	}
	return io.EOF
}

func (w *h2Wire) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := w.advance(); err != nil {
		return 0, err
	}
	n := copy(p, w.fragments[w.index].Raw()[w.offset:])
	w.offset += n
	w.seen = true
	return n, nil
}

func (w *h2Wire) timestamp() int64 {
	if w.advance() != nil {
		return 0
	}
	return w.fragments[w.index].CaptureInfo().Timestamp.UnixNano()
}

func headerHasToken(header http.Header, name, token string) bool {
	for _, value := range header.Values(name) {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

func upgradeSettings(req *http.Request) ([]http2.Setting, bool) {
	values := req.Header.Values("HTTP2-Settings")
	if len(values) != 1 || len(values[0]) > 2048 {
		return nil, false
	}
	data, err := base64.RawURLEncoding.DecodeString(values[0])
	if err != nil || len(data)%6 != 0 {
		return nil, false
	}
	var settings []http2.Setting
	for len(data) > 0 {
		s := http2.Setting{ID: http2.SettingID(binary.BigEndian.Uint16(data)), Val: binary.BigEndian.Uint32(data[2:])}
		if s.Valid() != nil {
			return nil, false
		}
		settings = append(settings, s)
		data = data[6:]
	}
	return settings, true
}

func validH2Upgrade(req *http.Request) bool {
	_, ok := upgradeSettings(req)
	return ok && req.Proto == "HTTP/1.1" && strings.EqualFold(req.Header.Get("Upgrade"), "h2c") && headerHasToken(req.Header, "Connection", "upgrade") && headerHasToken(req.Header, "Connection", "http2-settings")
}
