package sipaudit

import (
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/dreadl0ck/netcap/types"
)

const maxCalls = 256
const maxDescriptions = 8
const associationLifetime int64 = 3600e9

type Codec struct {
	Encoding string
	Rate     uint32
	Events   string
}
type media struct {
	ip       string
	port     int32
	codecs   map[uint32]Codec
	disabled bool
}
type description struct {
	at           int64
	seq          int32
	method       string
	answer, stop bool
	media        []media
}
type call struct {
	id           string
	scope        string
	latest       int64
	descriptions []description
}

// Associations stores signaling metadata only. Capture-time intervals, rather
// than arrival order or wall time, also support UDP replay after TCP readers drain.
type Associations struct {
	mu    sync.RWMutex
	calls map[string]*call
}

var Media = NewAssociations()

func NewAssociations() *Associations { return &Associations{calls: map[string]*call{}} }
func (a *Associations) Reset()       { a.mu.Lock(); defer a.mu.Unlock(); a.calls = map[string]*call{} }

func fromTag(from string) string {
	for _, part := range strings.Split(from, ";")[1:] {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(key, "tag") {
			return value
		}
	}
	return ""
}

func (a *Associations) Observe(s *types.SIP) {
	if s.CallID == "" || len(s.CallID) > 256 {
		return
	}
	tag := fromTag(s.From)
	if tag == "" || len(tag) > 128 {
		return
	}
	d := description{at: s.Timestamp, seq: s.CSeqNumber, method: s.CSeqMethod, answer: s.IsResponse}
	if !s.IsResponse && (s.MethodName == "BYE" || s.MethodName == "CANCEL") {
		d.stop = true
	} else {
		if d.method != "INVITE" && d.method != "UPDATE" {
			return
		}
		if s.IsResponse && (s.ResponseCode < 180 || s.ResponseCode >= 300) {
			return
		}
		contentType, _, _ := strings.Cut(s.ContentType, ";")
		if !strings.EqualFold(strings.TrimSpace(contentType), "application/sdp") {
			return
		}
		d.media = parseSDP(s.Body)
		if len(d.media) == 0 {
			return
		}
	}
	key := s.NetworkScope + "\x00" + s.CallID + "\x00" + tag
	a.mu.Lock()
	defer a.mu.Unlock()
	c := a.calls[key]
	if c == nil {
		if len(a.calls) >= maxCalls {
			oldKey, oldest := "", int64(1<<63-1)
			for k, v := range a.calls {
				if v.latest < oldest || (v.latest == oldest && k < oldKey) {
					oldKey, oldest = k, v.latest
				}
			}
			if d.at < oldest {
				return
			}
			delete(a.calls, oldKey)
		}
		c = &call{id: s.CallID, scope: s.NetworkScope, latest: d.at}
		a.calls[key] = c
	}
	// Retransmissions do not extend a negotiation's validity or consume slots.
	for _, old := range c.descriptions {
		if old.seq == d.seq && old.method == d.method && old.answer == d.answer && old.stop == d.stop && sameMedia(old.media, d.media) {
			return
		}
	}
	c.latest = max(c.latest, d.at)
	c.descriptions = append(c.descriptions, d)
	sort.SliceStable(c.descriptions, func(i, j int) bool { return c.descriptions[i].at < c.descriptions[j].at })
	if len(c.descriptions) > maxDescriptions {
		c.descriptions = c.descriptions[len(c.descriptions)-maxDescriptions:]
	}
}

func sameMedia(a, b []media) bool {
	if len(a) != len(b) {
		return false
	}
	for i, x := range a {
		y := b[i]
		if x.ip != y.ip || x.port != y.port || x.disabled != y.disabled || len(x.codecs) != len(y.codecs) {
			return false
		}
		for pt, codec := range x.codecs {
			if y.codecs[pt] != codec {
				return false
			}
		}
	}
	return true
}

// Lookup requires both advertised endpoints and a matching offer/answer codec.
// Ambiguous overlapping calls fail closed; NAT port guessing is not performed.
func (a *Associations) Lookup(scope, src, dst string, sport, dport int32, pt uint32, at int64) (string, Codec, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	var foundID string
	var foundCall *call
	var found Codec
	for _, c := range a.calls {
		if c.scope != scope {
			continue
		}
		var offer *description
		var answer *description
		for i := range c.descriptions {
			d := &c.descriptions[i]
			if d.at > at {
				break
			}
			if d.stop {
				offer, answer = nil, nil
				continue
			}
			if !d.answer {
				offer, answer = d, nil
				continue
			}
			if offer != nil && d.seq == offer.seq && d.method == offer.method {
				answer = d
			}
		}
		if offer == nil || answer == nil || at-offer.at > associationLifetime {
			continue
		}
		for i, x := range offer.media {
			if i >= len(answer.media) {
				break
			}
			y := answer.media[i]
			if x.disabled || y.disabled {
				continue
			}
			if src == x.ip && sport == x.port && dst == y.ip && dport == y.port {
				x, y = y, x // x is the receiver's payload map
			} else if !(src == y.ip && sport == y.port && dst == x.ip && dport == x.port) {
				continue
			}
			codec, ok := x.codecs[pt]
			if !ok {
				continue
			}
			compatible := false
			var allowed [16]bool
			for _, peer := range y.codecs {
				if peer.Encoding == codec.Encoding && peer.Rate == codec.Rate {
					if codec.Encoding == "telephone-event" {
						for event := range uint32(16) {
							if codec.AllowsEvent(event) && peer.AllowsEvent(event) {
								allowed[event] = true
							}
						}
					}
					compatible = true
				}
			}
			if codec.Encoding == "telephone-event" {
				var events []string
				for event, ok := range allowed {
					if ok {
						events = append(events, strconv.Itoa(event))
					}
				}
				compatible = len(events) > 0
				codec.Events = strings.Join(events, ",")
			}
			if !compatible {
				continue
			}
			if foundCall != nil && (foundCall != c || found != codec) {
				return "", Codec{}, false
			}
			foundID, found = c.id, codec
			foundCall = c
		}
	}
	return foundID, found, foundID != ""
}

func connection(fields []string) string {
	if len(fields) != 3 || fields[0] != "IN" || (fields[1] != "IP4" && fields[1] != "IP6") {
		return ""
	}
	ip, err := netip.ParseAddr(fields[2])
	if err != nil || ip.IsUnspecified() || ip.IsMulticast() || (fields[1] == "IP4") != ip.Is4() {
		return ""
	}
	return ip.String()
}

func parseSDP(body []byte) []media {
	if len(body) == 0 || len(body) > MaxBody {
		return nil
	}
	var result []media
	sessionIP := ""
	sessionDisabled := false
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if len(line) < 2 || line[1] != '=' {
			continue
		}
		fields := strings.Fields(line[2:])
		switch line[:2] {
		case "c=":
			ip := connection(fields)
			if len(result) == 0 {
				sessionIP = ip
			} else {
				result[len(result)-1].ip = ip
			}
		case "m=":
			if len(result) >= 8 {
				return nil
			}
			m := media{ip: sessionIP, disabled: sessionDisabled, codecs: map[uint32]Codec{}}
			if len(fields) >= 4 {
				port, err := strconv.ParseUint(fields[1], 10, 16)
				m.port = int32(port)
				m.disabled = m.disabled || err != nil || port == 0 || fields[0] != "audio" || (fields[2] != "RTP/AVP" && fields[2] != "RTP/AVPF")
				if len(fields) > 36 {
					return nil
				}
				for _, value := range fields[3:] {
					pt, err := strconv.ParseUint(value, 10, 7)
					if err == nil {
						m.codecs[uint32(pt)] = staticCodec(uint32(pt))
					}
				}
			} else {
				m.disabled = true
			}
			result = append(result, m)
		case "a=":
			if line == "a=inactive" || line == "a=sendonly" || line == "a=recvonly" {
				// Direction-limited sessions need directional offer/answer handling.
				if len(result) == 0 {
					sessionDisabled = true
				} else {
					result[len(result)-1].disabled = true
				}
			}
			if len(result) == 0 {
				continue
			}
			m := &result[len(result)-1]
			if len(fields) != 2 {
				continue
			}
			name, value, ok := strings.Cut(fields[0], ":")
			if !ok {
				continue
			}
			pt, err := strconv.ParseUint(value, 10, 7)
			if err != nil {
				continue
			}
			codec, offered := m.codecs[uint32(pt)]
			if !offered {
				continue
			}
			if name == "rtpmap" {
				parts := strings.Split(fields[1], "/")
				if len(parts) < 2 || len(parts) > 3 || len(parts[0]) > 32 {
					continue
				}
				rate, err := strconv.ParseUint(parts[1], 10, 32)
				if err != nil || rate == 0 || rate > 384000 {
					continue
				}
				codec.Encoding, codec.Rate = strings.ToLower(parts[0]), uint32(rate)
			} else if name == "fmtp" && len(fields[1]) <= 128 {
				codec.Events = fields[1]
			}
			m.codecs[uint32(pt)] = codec
		}
	}
	for i := range result {
		m := &result[i]
		if m.ip == "" {
			m.disabled = true
		}
		for pt, c := range m.codecs {
			if c.Encoding == "" || c.Rate == 0 {
				delete(m.codecs, pt)
			}
		}
	}
	return result
}

func staticCodec(pt uint32) Codec {
	switch pt {
	case 0:
		return Codec{Encoding: "pcmu", Rate: 8000}
	case 8:
		return Codec{Encoding: "pcma", Rate: 8000}
	case 9:
		return Codec{Encoding: "g722", Rate: 8000}
	case 18:
		return Codec{Encoding: "g729", Rate: 8000}
	}
	return Codec{}
}

func (c Codec) AllowsEvent(event uint32) bool {
	if event > 15 {
		return false
	}
	if c.Events == "" {
		return true
	} // RFC 4733 default events 0-15
	allowed := false
	for _, part := range strings.Split(c.Events, ",") {
		lo, hi, rangeValue := strings.Cut(part, "-")
		start, err := strconv.ParseUint(lo, 10, 8)
		if err != nil {
			return false
		}
		end := start
		if rangeValue {
			var err error
			end, err = strconv.ParseUint(hi, 10, 8)
			if err != nil {
				return false
			}
		}
		if start > end {
			return false
		}
		if uint64(event) >= start && uint64(event) <= end {
			allowed = true
		}
	}
	return allowed
}
