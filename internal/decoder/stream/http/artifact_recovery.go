package http

import "github.com/dreadl0ck/netcap/internal/decoder/core"

func (h *httpReader) crossCloseBody(server bool, start, headerEnd, end int) bool {
	if headerEnd <= start || end <= headerEnd {
		return false
	}
	side := 0
	if server {
		side = 1
	}
	fragments := h.directionalEvidence[side]
	seen := false
	for _, f := range fragments {
		if d, ok := f.(*core.StreamData); ok && d.HasGap(seen) {
			return false
		}
		seen = seen || len(f.Raw()) > 0
	}
	offset := 0
	qualified := false
	for _, f := range fragments {
		next := offset + len(f.Raw())
		if d, ok := f.(*core.StreamData); ok && d.TCPObservation != "" {
			if offset < headerEnd && next > start {
				return false
			}
			if offset < end && next > headerEnd {
				qualified = true
			}
		}
		offset = next
	}
	return qualified
}
