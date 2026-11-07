package dcerpc

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/gopacket/gopacket"
	"go.uber.org/zap"
)

const (
	smbPipeFrameLimit    = 1 << 20
	smbPipeByteLimit     = 8 << 20
	smbPipeStateLimit    = 1024
	smbPipeLifetimeLimit = 512
	smbPipeFragmentLimit = 32768
	smbStatusPending     = 0x103
	smbStatusOverflow    = 0x80000005
)

type smbPipeScope struct {
	version uint8
	session uint64
	tree    uint32
}

type smbPipeHandle struct {
	smbPipeScope
	id [16]byte
}

type smbPipeMID struct {
	version      uint8
	session, mid uint64
	pid, tree    uint32 // SMB1 MIDs are scoped by UID, TID and PID.
	command      uint16
}

type smbPipe struct {
	c              *core.ConversationInfo
	scope          smbPipeScope
	id             [16]byte
	proved, closed bool
	events         []smbPipeEvent
	cutoff         uint64
}

type smbPipeEvent struct {
	data     *core.StreamData
	sequence uint64
}

type smbPipeRequest struct {
	scope    smbPipeScope
	pipe     *smbPipe // snapshot the lifetime, never resolve a delayed reply by FID
	name     string
	data     []byte
	at       int64
	sequence uint64
	limit    uint32
	trans    *smbPipeTransaction
}

type smbPipeTransport struct {
	c                 *core.ConversationInfo
	trees             map[smbPipeScope]bool
	handles           map[smbPipeHandle]*smbPipe
	pending           map[smbPipeMID]*smbPipeRequest
	order             []*smbPipe
	stored, fragments int
	sequence          uint64
	initialLoss       bool
	stop              string
}

// DecodeSMBPipes supplies each observed plaintext pipe lifetime to the existing
// RPC parser. Names alone, unknown handles and opaque SMB transforms prove no RPC.
func DecodeSMBPipes(c *core.ConversationInfo) {
	if Decoder.Writer == nil {
		return
	}
	for _, pipe := range smbPipeConversations(c) {
		(&dcerpcReader{conversation: pipe}).Decode()
	}
}

func smbPipeConversations(c *core.ConversationInfo) []*core.ConversationInfo {
	t := &smbPipeTransport{c: c, trees: map[smbPipeScope]bool{}, handles: map[smbPipeHandle]*smbPipe{}, pending: map[smbPipeMID]*smbPipeRequest{}}
	type side struct {
		data []byte
		at   int64
		seen bool
	}
	var sides [2]side
	for _, f := range c.Data {
		s := &sides[0]
		if f.Direction() == reassembly.TCPDirServerToClient {
			s = &sides[1]
		}
		if gap, ok := f.(*core.StreamData); ok && gap.SkippedBytes != 0 {
			if gap.SkippedBytes == -1 && !s.seen {
				t.initialLoss = true
			} else {
				t.stop = "capture-gap"
				break
			}
		}
		raw := f.Raw()
		if len(raw) != 0 {
			s.seen = true
		}
		// Consume one NBSS frame at a time, independent of TCP delivery chunk size.
		for len(raw) > 0 && t.stop == "" {
			if len(s.data) == 0 {
				s.at = core.FragmentTime(f)
			}
			if len(s.data) < 4 {
				n := min(4-len(s.data), len(raw))
				s.data = append(s.data, raw[:n]...)
				raw = raw[n:]
				if len(s.data) < 4 {
					break
				}
			}
			n := int(s.data[1])<<16 | int(s.data[2])<<8 | int(s.data[3])
			kind := s.data[0]
			if n > smbPipeFrameLimit || (kind != 0 && kind != 0x81 && kind != 0x82 && kind != 0x85) {
				t.stop = "invalid-nbss"
				break
			}
			count := min(4+n-len(s.data), len(raw))
			s.data = append(s.data, raw[:count]...)
			raw = raw[count:]
			if len(s.data) < 4+n {
				break
			}
			if kind == 0 {
				frame := s.data[4:]
				if len(frame) < 4 {
					t.stop = "invalid-smb"
					break
				}
				switch string(frame[:4]) {
				case "\xfeSMB":
					t.smb2(frame, f.Direction(), s.at)
				case "\xffSMB":
					t.smb1(frame, f.Direction(), s.at)
				case "\xfdSMB", "\xfcSMB":
					t.stop = "opaque-transform"
				default:
					t.stop = "invalid-smb"
				}
			}
			s.data = s.data[:0]
		}
		if t.stop != "" {
			break
		}
	}
	if t.stop == "" && (len(sides[0].data) != 0 || len(sides[1].data) != 0) {
		t.stop = "truncated-nbss"
	}
	if t.stop != "" {
		dcerpcLog.Info("SMB pipe transport stopped at evidence boundary", zap.String("flow", c.Ident), zap.String("reason", t.stop), zap.Int("pipeLifetimes", len(t.order)), zap.Int("payloadFragments", t.fragments))
	}
	for _, r := range t.pending {
		if r.pipe != nil {
			t.fail(r, "incomplete-io")
		}
	}
	var result []*core.ConversationInfo
	for _, p := range t.order {
		if !p.proved {
			continue
		}
		sort.SliceStable(p.events, func(i, j int) bool { return p.events[i].sequence < p.events[j].sequence })
		for _, e := range p.events {
			if p.cutoff == 0 || e.sequence < p.cutoff {
				p.c.Data = append(p.c.Data, e.data)
			}
		}
		if len(p.c.Data) == 0 {
			continue
		}
		if t.initialLoss {
			p.c.Ident += "|initial-loss-unknown"
		}
		if t.stop != "" {
			p.c.Ident += "|smb-" + t.stop
		}
		result = append(result, p.c)
	}
	return result
}

func (t *smbPipeTransport) newPipe(scope smbPipeScope, name string) *smbPipe {
	if len(t.order) >= smbPipeLifetimeLimit {
		t.stop = "state-limit"
		return nil
	}
	c := *t.c
	c.Data, c.ClientData, c.ServerData = nil, nil, nil
	c.Ident = fmt.Sprintf("%s|pipe:%s:smb%d:%x:%x:%d", c.Ident, name, scope.version, scope.session, scope.tree, len(t.order)+1)
	p := &smbPipe{c: &c, scope: scope}
	t.order = append(t.order, p)
	return p
}

func (t *smbPipeTransport) remember(mid smbPipeMID, r *smbPipeRequest) {
	if t.pending[mid] != nil {
		t.stop = "ambiguous-mid"
		return
	}
	if len(t.pending) >= smbPipeStateLimit {
		t.stop = "state-limit"
		return
	}
	t.pending[mid] = r
}

func (t *smbPipeTransport) hold(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	if len(data) > smbPipeByteLimit-t.stored {
		t.stop = "byte-limit"
		return nil
	}
	t.stored += len(data)
	return append([]byte(nil), data...)
}

func (t *smbPipeTransport) emit(p *smbPipe, data []byte, dir reassembly.TCPFlowDirection, at int64, sequence ...uint64) {
	if p == nil || len(data) == 0 {
		return
	}
	if t.fragments >= smbPipeFragmentLimit {
		t.stop = "fragment-limit"
		return
	}
	t.fragments++
	seq := t.sequence
	if len(sequence) != 0 {
		seq = sequence[0]
	}
	p.events = append(p.events, smbPipeEvent{&core.StreamData{RawData: data, Dir: dir, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(0, at)}}, seq})
}

func (t *smbPipeTransport) fail(r *smbPipeRequest, reason string) {
	if r.pipe == nil {
		return
	}
	if r.pipe.cutoff == 0 && r.pipe.closed {
		r.pipe.c.Ident += "|smb-" + reason
	}
	if r.pipe.cutoff == 0 || r.sequence < r.pipe.cutoff {
		r.pipe.cutoff = r.sequence
	}
	t.closePipe(r.pipe, reason)
}

func (t *smbPipeTransport) bindHandle(scope smbPipeScope, id []byte, p *smbPipe) {
	h := smbHandle(scope, id)
	if old := t.handles[h]; old != nil && old != p {
		t.closePipe(old, "handle-reused")
	}
	if p != nil {
		p.id = h.id
		p.proved = true
		t.handles[h] = p
	} else {
		delete(t.handles, h)
	}
}

func (t *smbPipeTransport) closePipe(p *smbPipe, reason string) {
	if p == nil || p.closed {
		return
	}
	p.closed = true
	if reason != "" {
		p.c.Ident += "|smb-" + reason
	}
	for h, current := range t.handles {
		if current == p {
			delete(t.handles, h)
		}
	}
}

func (t *smbPipeTransport) forget(scope smbPipeScope, session bool) {
	match := func(s smbPipeScope) bool {
		return s.version == scope.version && s.session == scope.session && (session || s.tree == scope.tree)
	}
	for s := range t.trees {
		if match(s) {
			delete(t.trees, s)
		}
	}
	for _, p := range t.order {
		if match(p.scope) {
			t.closePipe(p, "")
		}
	}
	for mid, r := range t.pending {
		if match(r.scope) {
			t.fail(r, "incomplete-io")
			delete(t.pending, mid)
		}
	}
}

func (t *smbPipeTransport) tree(scope smbPipeScope, pipe bool) {
	// A new successful connect is a new tree incarnation even if the TID repeats.
	t.forget(scope, false)
	if len(t.trees) >= smbPipeStateLimit {
		t.stop = "state-limit"
		return
	}
	t.trees[scope] = pipe
}

func smbHandle(scope smbPipeScope, id []byte) smbPipeHandle {
	h := smbPipeHandle{smbPipeScope: scope}
	copy(h.id[:], id)
	return h
}

func smbSlice(frame []byte, offset, length uint32, minimum int) []byte {
	if offset < uint32(minimum) || offset > uint32(len(frame)) || length > uint32(len(frame))-offset {
		return nil
	}
	return frame[offset : offset+length]
}

func smbUnicode(b []byte) string {
	if len(b)%2 != 0 {
		return ""
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	for i := 0; i < len(u); i++ {
		if u[i] >= 0xd800 && u[i] <= 0xdbff {
			if i+1 == len(u) || u[i+1] < 0xdc00 || u[i+1] > 0xdfff {
				return ""
			}
			i++
		} else if u[i] >= 0xdc00 && u[i] <= 0xdfff {
			return ""
		}
	}
	return string(utf16.Decode(u))
}

func smbPipeName(name string) string {
	name = strings.TrimPrefix(name, "\\")
	if strings.HasPrefix(strings.ToLower(name), "pipe\\") {
		name = name[5:]
	}
	if len(name) == 0 || len(name) > 1024 {
		return ""
	}
	for _, part := range strings.Split(name, "\\") {
		if part == "" || part == "." || part == ".." {
			return ""
		}
	}
	for _, r := range name {
		if unicode.IsControl(r) || strings.ContainsRune("/:*?\"<>|", r) {
			return ""
		}
	}
	return name
}
