// Package otframe frames ordered TCP deliveries without retaining the conversation.
package otframe

import (
	"bufio"
	"errors"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket/layers"
)

type Frame struct {
	Data    []byte
	At      int64
	Side    int
	Context *types.PacketContext
}
type Half struct {
	buf     []byte
	start   int64
	stopped bool
	seen    bool
}

// Walk calls reset before crossing loss and at EOF, including when an application
// transfer is pending but the TCP framer itself is on a boundary.
func Walk(c *core.ConversationInfo, split bufio.SplitFunc, limit int, emit func(Frame), reset func(Frame, string)) {
	var halves [2]Half
	contexts := [2]*types.PacketContext{{SrcIP: c.ClientIP, DstIP: c.ServerIP, SrcPort: c.ClientPort, DstPort: c.ServerPort, CommunityID: c.CommunityID, NetworkScope: c.NetworkScope}, {SrcIP: c.ServerIP, DstIP: c.ClientIP, SrcPort: c.ServerPort, DstPort: c.ClientPort, CommunityID: c.CommunityID, NetworkScope: c.NetworkScope}}
	release := func(h *Half) { c.StateBudget.Release(int64(cap(h.buf))); h.buf = nil }
	defer func() {
		for i := range halves {
			release(&halves[i])
		}
	}()
	for f := range c.Fragments() {
		if c.FragmentError != nil {
			return
		}
		i := 0
		if core.FromServer(f) {
			i = 1
		}
		h := &halves[i]
		at := core.FragmentTime(f)
		fr := Frame{At: at, Side: i, Context: contexts[i]}
		if sd, ok := f.(*core.StreamData); ok && (sd.SkippedBytes != 0 || sd.DiscardedBytes != 0 || sd.TCPObservation != "") {
			if len(h.buf) > 0 {
				fr.At = h.start
			}
			reset(fr, "capture gap")
			release(h)
			h.stopped = false
			fr.At = at
			if sd.TCPObservation != "" {
				continue
			}
		}
		if h.stopped {
			continue
		}
		data := f.Raw()
		for len(data) > 0 && c.FragmentError == nil {
			h.seen = true
			// The common case is a contiguous PDU. Only copy an incomplete token.
			if len(h.buf) == 0 {
				adv, tok, err := split(data, false)
				if err != nil {
					reset(fr, err.Error())
					h.stopped = true
					break
				}
				if adv > 0 {
					if tok != nil {
						fr.Data = tok
						emit(fr)
					}
					data = data[adv:]
					continue
				}
				h.start = at
			}
			room := limit - len(h.buf)
			if room <= 0 {
				reset(fr, "PDU size limit")
				release(h)
				h.stopped = true
				break
			}
			n := min(len(data), room)
			need := len(h.buf) + n
			if need > cap(h.buf) {
				size := min(limit, max(need, max(32, cap(h.buf)*2)))
				if err := c.StateBudget.Reserve(int64(size)); err != nil {
					reset(fr, "state budget")
					c.FragmentError = err
					return
				}
				b := make([]byte, len(h.buf), size)
				copy(b, h.buf)
				release(h)
				h.buf = b
			}
			h.buf = append(h.buf, data[:n]...)
			data = data[n:]
			consumed := 0
			for consumed < len(h.buf) {
				adv, tok, err := split(h.buf[consumed:], false)
				if err != nil {
					reset(Frame{At: h.start, Side: i, Context: fr.Context}, err.Error())
					release(h)
					h.stopped = true
					break
				}
				if adv == 0 {
					break
				}
				if tok != nil {
					emit(Frame{Data: tok, At: h.start, Side: i, Context: fr.Context})
				}
				consumed += adv
				h.start = at
			}
			if h.stopped {
				break
			}
			if consumed > 0 {
				copy(h.buf, h.buf[consumed:])
				h.buf = h.buf[:len(h.buf)-consumed]
			}
		}
	}
	for i, h := range halves {
		if !h.seen {
			continue
		}
		fr := Frame{Side: i, At: h.start, Context: contexts[i]}
		if len(h.buf) > 0 {
			_, _, err := split(h.buf, true)
			reason := "truncated PDU"
			if err != nil && !errors.Is(err, layers.ErrOTStreamTruncated) {
				reason = err.Error()
			}
			reset(fr, reason)
		} else {
			reset(fr, "EOF")
		}
	}
}
