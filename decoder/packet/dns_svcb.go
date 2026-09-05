package packet

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/gopacket/gopacket/layers"
	"github.com/yosida95/uritemplate/v3"

	"github.com/dreadl0ck/netcap/types"
)

func dnsSVCB(rr layers.DNSResourceRecord) *types.DNSSVCB {
	if rr.Type != layers.DNSTypeSVCB && rr.Type != layers.DNSTypeHTTPS {
		return nil
	}
	s := &types.DNSSVCB{Priority: uint32(rr.SVCB.Priority), Target: string(rr.SVCB.Target)}
	keys := make(map[uint32]bool, len(rr.SVCB.Params))
	for _, p := range rr.SVCB.Params {
		keys[uint32(p.Key)] = true
	}
	for i, p := range rr.SVCB.Params {
		v := p.Value
		d := &types.DNSSVCBParam{Key: uint32(p.Key), Value: bytes.Clone(v)}
		s.Params = append(s.Params, d)
		if i > 0 && p.Key <= rr.SVCB.Params[i-1].Key {
			s.Invalid = true
		}
		valid := true
		switch p.Key {
		case layers.DNSSvcParamKeyMandatory:
			valid = len(v) > 0 && len(v)%2 == 0
			var previous uint32
			for j := 0; valid && j < len(v); j += 2 {
				key := uint32(binary.BigEndian.Uint16(v[j:]))
				valid = key > previous && key != 65535 && keys[key]
				d.Mandatory = append(d.Mandatory, key)
				previous = key
			}
		case layers.DNSSvcParamKeyAlpn:
			valid = len(v) > 0
			for len(v) > 0 && valid {
				n := int(v[0])
				v = v[1:]
				valid = n > 0 && n <= len(v)
				if valid {
					d.ALPN = append(d.ALPN, bytes.Clone(v[:n]))
					v = v[n:]
				}
			}
		case layers.DNSSvcParamKeyNoDefaultAlpn:
			valid = len(v) == 0 && keys[1]
			d.NoDefaultALPN = valid
		case layers.DNSSvcParamKeyPort:
			valid = len(v) == 2
			if valid {
				d.Port = uint32(binary.BigEndian.Uint16(v))
			}
		case layers.DNSSvcParamKeyIPv4Hint, layers.DNSSvcParamKeyIPv6Hint:
			size := net.IPv4len
			if p.Key == layers.DNSSvcParamKeyIPv6Hint {
				size = net.IPv6len
			}
			valid = len(v) > 0 && len(v)%size == 0
			if valid {
				for j := 0; j < len(v); j += size {
					ip := net.IP(v[j : j+size]).String()
					if size == net.IPv4len {
						d.IPv4Hints = append(d.IPv4Hints, ip)
					} else {
						d.IPv6Hints = append(d.IPv6Hints, ip)
					}
				}
			}
		case layers.DNSSvcParamKeyECH:
			valid = len(v) >= 6 && int(binary.BigEndian.Uint16(v)) == len(v)-2
			if valid {
				v = v[2:]
				for len(v) > 0 && valid {
					valid = len(v) >= 4
					if valid {
						n := int(binary.BigEndian.Uint16(v[2:]))
						valid = n <= len(v)-4
						if valid {
							v = v[4+n:]
						}
					}
				}
			}
			d.ECH = bytes.Clone(p.Value)
		case layers.DNSSvcParamKeyDoHPath:
			path := string(v)
			template, err := uritemplate.New(path)
			valid = utf8.Valid(v) && err == nil && strings.HasPrefix(path, "/")
			if valid {
				expanded, err := template.Expand(uritemplate.Values{"dns": uritemplate.String("AA")})
				u, parseErr := url.ParseRequestURI(expanded)
				valid = err == nil && parseErr == nil && slices.Contains(template.Varnames(), "dns") &&
					u.Host == "" && !strings.HasPrefix(expanded, "//") && !strings.ContainsAny(expanded, "# \t\r\n")
			}
			d.DoHPath = path
		case layers.DNSSvcParamKeyInvalidKey:
			valid = false
		default:
			continue
		}
		if !valid {
			// Discard partial convenience decoding, never the original value.
			*d = types.DNSSVCBParam{Key: d.Key, Value: d.Value, Error: "invalid service parameter"}
			s.Invalid = true
		} else {
			d.Decoded = true
		}
	}
	return s
}
