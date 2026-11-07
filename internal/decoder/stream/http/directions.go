package http

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"strings"

	"golang.org/x/net/http2"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/internal/reassembly"
)

func (h *httpReader) decodeDirections() {
	var directions [2]core.DataFragments
	if h.conversation.ClientData != nil || h.conversation.ServerData != nil {
		directions[0], directions[1] = h.conversation.ClientData, h.conversation.ServerData
	} else {
		for _, f := range h.conversation.Data {
			side := 0
			if f.Direction() == reassembly.TCPDirServerToClient {
				side = 1
			}
			directions[side] = append(directions[side], f)
		}
	}
	prefix := func(f core.DataFragments) []byte {
		var b []byte
		for _, d := range f {
			if len(b) > 0 {
				if s, ok := d.(*core.StreamData); ok && (s.SkippedBytes != 0 || s.DiscardedBytes > 0) {
					break
				}
			}
			n := min(len(d.Raw()), 16384-len(b))
			b = append(b, d.Raw()[:n]...)
			if len(b) == 16384 {
				break
			}
		}
		return b
	}
	client, server := prefix(directions[0]), prefix(directions[1])
	for _, reverse := range []bool{false, true} {
		if bytes.HasPrefix(client, []byte(http2.ClientPreface)) || bytes.HasPrefix(server, []byte(http2.ClientPreface)) {
			break
		}
		request, response := 0, 1
		if reverse {
			request, response = 1, 0
		}
		data := [2][]byte{client, server}
		a, b := httpStart(data[request], false), httpStart(data[response], true)
		if a >= 0 && b >= 0 && (a > 0 || b > 0) {
			directions[request] = trimFragments(directions[request], a)
			directions[response] = trimFragments(directions[response], b)
			client, server = prefix(directions[0]), prefix(directions[1])
			h.preface = true
			h.directionBroken = [2]bool{true, true}
			break
		}
	}
	if bytes.HasPrefix(server, []byte(http2.ClientPreface)) || containsHTTPMethod(server) || containsHTTPProtocolName(client) && !containsHTTPMethod(client) {
		directions[0], directions[1] = directions[1], directions[0]
		c := *h.conversation
		c.ClientIP, c.ServerIP = c.ServerIP, c.ClientIP
		c.ClientPort, c.ServerPort = c.ServerPort, c.ClientPort
		c.ClientMAC, c.ServerMAC = c.ServerMAC, c.ClientMAC
		c.ClientData, c.ServerData = c.ServerData, c.ClientData
		c.FirstClientPacket, c.FirstServerPacket = c.FirstServerPacket, c.FirstClientPacket
		h.conversation = &c
	}
	if bytes.HasPrefix(prefix(directions[0]), []byte(http2.ClientPreface)) {
		h.decodeH2(directions, nil)
		return
	}
	type run struct {
		fragments core.DataFragments
		lost      bool
	}
	var runs [2][]run
	for side, fragments := range directions {
		var chunk core.DataFragments
		lost := false
		seenBytes := false
		for _, f := range fragments {
			if d, ok := f.(*core.StreamData); ok && (d.SkippedBytes != 0 || d.DiscardedBytes > 0) {
				if d.SkippedBytes == -1 && !seenBytes && d.DiscardedBytes == 0 {
					h.initialUnknown = true
				} else {
					h.captureLoss = true
					if len(chunk) > 0 {
						runs[side] = append(runs[side], run{chunk, lost})
						chunk = nil
					}
					lost = true
				}
			}
			chunk = append(chunk, f)
			seenBytes = seenBytes || len(f.Raw()) > 0
		}
		if len(chunk) > 0 {
			runs[side] = append(runs[side], run{chunk, lost})
		}
	}
	var upgrade *httpRequest
	var h2Directions [2]core.DataFragments
	for side, chunks := range runs {
		stopDirection := false
		for index, chunk := range chunks {
			if stopDirection {
				break
			}
			h.directionBroken[side] = h.directionBroken[side] || chunk.lost
			b, pos := streamutils.FragmentReader(chunk.fragments, side == 1)
			remainder := func() core.DataFragments {
				remaining := trimFragments(chunk.fragments, pos.Offset())
				for _, rest := range chunks[index+1:] {
					remaining = append(remaining, rest.fragments...)
				}
				return remaining
			}
			for {
				skipped, ok := seekHTTPLine(b, side == 1)
				if skipped {
					h.directionBroken[side] = true
					h.pairingQualification = "unpaired_after_unrecognized_bytes"
				}
				if !ok {
					break
				}
				before := pos.Offset()
				var err error
				if side == 0 {
					err = h.readRequest(b, pos)
				} else {
					err = h.readResponse(b, pos)
				}
				if err != nil {
					h.directionBroken[side] = true
					h.pairingQualification = "unpaired_after_parse_error"
					if err == errUnsafeHTTPFraming {
						h.pairingQualification = "unpaired_after_ambiguous_framing"
						stopDirection = true
					}
					// A parser/body failure leaves no trustworthy next-message boundary.
					break
				}
				if side == 0 && len(h.requests) > 0 {
					req := h.requests[len(h.requests)-1]
					if validH2Upgrade(req.request) {
						upgrade = req
						h2Directions[0] = remainder()
						stopDirection = true
						break
					}
				}
				if side == 1 && len(h.responses) > 0 {
					res := h.responses[len(h.responses)-1].response
					if res.StatusCode == http.StatusSwitchingProtocols {
						if upgrade != nil && res.Request == upgrade.request && strings.EqualFold(res.Header.Get("Upgrade"), "h2c") && headerHasToken(res.Header, "Connection", "upgrade") {
							h2Directions[1] = remainder()
							h.decodeH2(h2Directions, upgrade)
						}
						stopDirection = true
						break
					}
					if res.Request != nil && res.Request.Method == methodCONNECT && res.StatusCode >= 200 && res.StatusCode < 300 {
						stopDirection = true
						break
					}
				}
				if pos.Offset() == before {
					break
				}
			}
		}
	}
}

type offsetFragment struct {
	core.DataFragment
	bytes []byte
}

func (f offsetFragment) Raw() []byte { return f.bytes }
func trimFragments(fragments core.DataFragments, n int) core.DataFragments {
	for i, f := range fragments {
		if n < len(f.Raw()) {
			out := append(core.DataFragments{}, fragments[i:]...)
			if n > 0 {
				out[0] = offsetFragment{f, f.Raw()[n:]}
			}
			return out
		}
		n -= len(f.Raw())
	}
	return nil
}

// Resynchronization is line-boundary-only and bounded per attempt. Bodies are
// consumed by net/http first; request-like bytes inside a complete body stay data.
func seekHTTPLine(b *bufio.Reader, response bool) (skipped, found bool) {
	for scanned := 0; scanned < 1<<20; {
		prefix, err := b.Peek(b.Size())
		if len(prefix) == 0 {
			return skipped, false
		}
		if end := bytes.IndexByte(prefix, '\n'); end >= 0 {
			line := prefix[:end+1]
			valid := containsHTTPMethod(line)
			if response {
				valid = containsHTTPProtocolName(line)
			}
			if valid {
				return skipped, true
			}
		}
		line, e := b.ReadSlice('\n')
		scanned += len(line)
		skipped = true
		if e == io.EOF || err == io.EOF && len(line) == 0 {
			return skipped, false
		}
	}
	return skipped, false
}
