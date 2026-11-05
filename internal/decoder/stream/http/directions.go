package http

import (
	"bufio"
	"bytes"
	"io"

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
				if s, ok := d.(*core.StreamData); ok && s.SkippedBytes != 0 {
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
	if containsHTTPMethod(server) || containsHTTPProtocolName(client) && !containsHTTPMethod(client) {
		directions[0], directions[1] = directions[1], directions[0]
		c := *h.conversation
		c.ClientIP, c.ServerIP = c.ServerIP, c.ClientIP
		c.ClientPort, c.ServerPort = c.ServerPort, c.ClientPort
		c.ClientMAC, c.ServerMAC = c.ServerMAC, c.ClientMAC
		c.ClientData, c.ServerData = c.ServerData, c.ClientData
		c.FirstClientPacket, c.FirstServerPacket = c.FirstServerPacket, c.FirstClientPacket
		h.conversation = &c
	}
	var runs [2][]core.DataFragments
	for side, fragments := range directions {
		var run core.DataFragments
		for _, f := range fragments {
			if d, ok := f.(*core.StreamData); ok && d.SkippedBytes != 0 {
				h.pairingBroken = true
				if len(run) > 0 {
					runs[side] = append(runs[side], run)
					run = nil
				}
			}
			run = append(run, f)
		}
		if len(run) > 0 {
			runs[side] = append(runs[side], run)
		}
	}
	for side, chunks := range runs {
		for _, chunk := range chunks {
			b, pos := streamutils.FragmentReader(chunk, side == 1)
			for {
				skipped, ok := seekHTTPLine(b, side == 1)
				if skipped {
					h.pairingBroken = true
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
					h.pairingBroken = true
				}
				if pos.Offset() == before {
					break
				}
			}
		}
	}
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
