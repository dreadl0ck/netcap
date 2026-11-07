package firewallaudit

import (
	"encoding/hex"
	"errors"
	"math"
	"net/netip"
	"reflect"
	"sort"
	"strconv"

	"github.com/dreadl0ck/netcap/internal/policy"
	"github.com/gogo/protobuf/proto"
)

// PacketContext must come from the caller's packet tuple, never parsed from a
// protocol banner, Flow string, remote-address text, or unvalidated Fields.
type PacketContext struct{ SrcIP, DstIP string }

type Projection struct {
	Event     policy.Event
	Truncated bool
	allowed   map[string]bool
}

// Project reads but never retains or mutates the message. The decoder must own
// the record for the duration of the callback, as for its existing writer.
func Project(m proto.Message, packet *PacketContext) (Projection, error) {
	registryOnce.Do(initRegistry)
	v := reflect.ValueOf(m)
	if !v.IsValid() {
		return Projection{}, errors.New("firewallaudit: nil record")
	}
	s, ok := recordTypes[v.Type()]
	if !ok || v.Kind() != reflect.Ptr || v.IsNil() {
		return Projection{}, errors.New("firewallaudit: unsupported or nil record")
	}
	p := Projection{Event: policy.Event{Protocol: "audit", RecordType: s.RecordType, Phase: "request", Fields: make(map[string]string)}, allowed: recordFields[v.Type()]}
	nodes := 0
	flatten(v, "", 0, &nodes, &p)
	if src, ok := m.(interface{ GetSrcIP() string }); ok {
		p.Event.Network.SrcIP = validIP(src.GetSrcIP())
	}
	if dst, ok := m.(interface{ GetDstIP() string }); ok {
		p.Event.Network.DstIP = validIP(dst.GetDstIP())
	}
	if packet != nil {
		if p.Event.Network.SrcIP == "" {
			p.Event.Network.SrcIP = validIP(packet.SrcIP)
		}
		if p.Event.Network.DstIP == "" {
			p.Event.Network.DstIP = validIP(packet.DstIP)
		}
	}
	p.Event.ClientIP = p.Event.Network.SrcIP
	if ports, ok := m.(interface {
		GetSrcPort() int32
		GetDstPort() int32
	}); ok {
		a, b := int(ports.GetSrcPort()), int(ports.GetDstPort())
		if a >= 0 && a <= 65535 {
			p.Event.Network.SrcPort = a
		}
		if b >= 0 && b <= 65535 {
			p.Event.Network.DstPort = b
		}
	}
	if a, err := netip.ParseAddr(p.Event.Network.SrcIP); err == nil {
		p.Event.Network.IPVersion = 4
		if a.Is6() {
			p.Event.Network.IPVersion = 6
		}
	}
	if tls, ok := m.(interface{ GetSNI() string }); ok && len(tls.GetSNI()) <= MaxValueBytes {
		p.Event.TLS.ServerName = tls.GetSNI()
		p.Event.TLS.Encrypted = true
	}
	if ja4, ok := m.(interface{ GetJa4() string }); ok && len(ja4.GetJa4()) <= MaxValueBytes {
		p.Event.TLS.JA4 = ja4.GetJa4()
	}
	if alpn, ok := m.(interface{ GetALPNs() []string }); ok {
		values := alpn.GetALPNs()
		if len(values) > 0 && len(values[0]) <= MaxValueBytes {
			p.Event.TLS.ALPN = values[0]
		}
	}
	if encrypted, ok := m.(interface{ GetIsEncrypted() bool }); ok {
		p.Event.TLS.Encrypted = encrypted.GetIsEncrypted()
	}
	if transport, ok := m.(interface{ GetTransport() string }); ok {
		value := transport.GetTransport()
		if value == "tcp" || value == "udp" {
			p.Event.Network.Transport = value
		}
	}
	p.Event.Attributes = map[string]string{"audit.schema_version": capabilities.Version, "audit.truncated": strconv.FormatBool(p.Truncated)}
	return p, nil
}

func validIP(raw string) string {
	if len(raw) > 64 {
		return ""
	}
	a, err := netip.ParseAddr(raw)
	if err != nil || a.Zone() != "" || a.Is4In6() || !a.IsGlobalUnicast() {
		return ""
	}
	return a.String()
}

func (p *Projection) put(path, value string) {
	if !p.allowed[path] || len(path) > 128 || len(value) > MaxValueBytes || len(p.Event.Fields) >= MaxFields {
		p.Truncated = true
		return
	}
	p.Event.Fields[path] = value
}

func scalar(v reflect.Value) (string, bool) {
	switch v.Kind() {
	case reflect.String:
		if v.Len() > MaxValueBytes {
			return "", false
		}
		return v.String(), true
	case reflect.Bool:
		return strconv.FormatBool(v.Bool()), true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(v.Int(), 10), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.FormatUint(v.Uint(), 10), true
	case reflect.Float32, reflect.Float64:
		f := v.Float()
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return "", false
		}
		return strconv.FormatFloat(f, 'g', -1, v.Type().Bits()), true
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 && v.Len() <= MaxValueBytes/2 {
			return hex.EncodeToString(v.Bytes()), true
		}
	}
	return "", false
}

func flatten(v reflect.Value, path string, depth int, nodes *int, p *Projection) {
	if depth > MaxDepth || *nodes >= MaxNodes || len(path) > 128 || len(p.Event.Fields) >= MaxFields {
		p.Truncated = true
		return
	}
	*nodes++
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return
		}
		v = v.Elem()
	}
	if scalarType(v.Type()) != "" {
		if value, ok := scalar(v); ok {
			p.put(path, value)
		} else {
			p.Truncated = true
		}
		return
	}
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			f := v.Type().Field(i)
			if f.Tag.Get("protobuf") != "" {
				flatten(v.Field(i), join(path, f.Name), depth+1, nodes, p)
			}
			if *nodes >= MaxNodes || len(p.Event.Fields) >= MaxFields {
				p.Truncated = true
				break
			}
		}
	case reflect.Slice, reflect.Array:
		p.put(path+".Length", strconv.Itoa(v.Len()))
		if v.Len() > MaxItems {
			p.Truncated = true
		}
		for i := 0; i < v.Len() && i < MaxItems; i++ {
			flatten(v.Index(i), path+"["+strconv.Itoa(i)+"]", depth+1, nodes, p)
		}
	case reflect.Map:
		p.put(path+".Length", strconv.Itoa(v.Len()))
		// Do not scan attacker-sized maps to select or sort their keys.
		if v.Len() > MaxItems {
			p.Truncated = true
			return
		}
		keys := v.MapKeys()
		for _, key := range keys {
			if _, ok := scalar(key); !ok {
				p.Truncated = true
				return
			}
		}
		sort.Slice(keys, func(i, j int) bool { a, _ := scalar(keys[i]); b, _ := scalar(keys[j]); return a < b })
		for i, k := range keys {
			prefix := path + "[" + strconv.Itoa(i) + "]"
			flatten(k, prefix+".Key", depth+1, nodes, p)
			flatten(v.MapIndex(k), prefix+".Value", depth+1, nodes, p)
		}
	}
}
