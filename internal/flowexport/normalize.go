package flowexport

import (
	"fmt"
	"math"
	"net/netip"
)

func normalize(fields []Field, version uint16, state *domainState, env Envelope, domain, seq uint32, templateID uint16, ordinal int, uptime uint32, exportNs int64) (Observation, error) {
	format := fmt.Sprintf("netflow-v%d", version)
	if version == 10 {
		format = "ipfix"
	}
	obs := Observation{Version: 1, Envelope: env, Format: format, Domain: domain, Sequence: seq, TemplateID: templateID, RecordOrdinal: ordinal, ExportNs: &exportNs,
		CounterSemantics: "exported-delta-as-reported", Sampling: state.sampling, ActiveTimeout: state.active, IdleTimeout: state.idle, Fields: fields,
		Limitations: []string{"port is not proof of application protocol", "TCP flags are bits observed, not packet order", "exporter count scaling is not inferred"}, TimeBasis: "unavailable"}
	var first, last *uint64
	seen := make(map[uint16]bool)
	for _, f := range fields {
		if f.EnterpriseProvided || f.Scope {
			continue
		}
		if seen[f.ID] {
			obs.Limitations = append(obs.Limitations, "repeated information element: normalization uses the first occurrence")
			continue
		}
		seen[f.ID] = true
		switch f.ID {
		case 8, 12, 15, 27, 28, 62:
			addr, ok := netip.AddrFromSlice(f.Value)
			if !ok || ((f.ID == 8 || f.ID == 12 || f.ID == 15) && !addr.Is4()) || ((f.ID == 27 || f.ID == 28 || f.ID == 62) && !addr.Is6()) {
				return obs, fmt.Errorf("invalid address field %d", f.ID)
			}
			switch f.ID {
			case 8, 27:
				obs.SrcIP = addr.String()
			case 12, 28:
				obs.DstIP = addr.String()
			default:
				obs.NextHop = addr.String()
			}
		case 1, 2, 4, 6, 7, 9, 10, 11, 13, 14, 16, 17, 21, 22, 29, 30, 32, 34, 35, 36, 37, 49, 50, 85, 86, 139, 150, 151, 152, 153, 158, 159, 176, 177, 178, 179, 180, 181, 182, 183:
			n, err := number(f.Value)
			if err != nil {
				return obs, fmt.Errorf("field %d: %w", f.ID, err)
			}
			switch f.ID {
			case 1:
				obs.Bytes = ptr(n)
			case 2:
				obs.Packets = ptr(n)
			case 85:
				if obs.Bytes == nil {
					obs.Bytes = ptr(n)
				}
				obs.CounterSemantics = "exported-cumulative-as-reported"
			case 86:
				if obs.Packets == nil {
					obs.Packets = ptr(n)
				}
				obs.CounterSemantics = "exported-cumulative-as-reported"
			case 4:
				if n > 255 {
					return obs, fmt.Errorf("invalid protocol")
				}
				obs.Protocol = ptr(n)
			case 6:
				if n > 65535 {
					return obs, fmt.Errorf("invalid TCP flags")
				}
				obs.TCPFlags = ptr(n & 0x0fff)
			case 7, 180, 182:
				if n > 65535 {
					return obs, fmt.Errorf("invalid source port")
				}
				obs.SrcPort = ptr(n)
			case 11, 181, 183:
				if n > 65535 {
					return obs, fmt.Errorf("invalid destination port")
				}
				obs.DstPort = ptr(n)
			case 9, 29:
				if n > 128 {
					return obs, fmt.Errorf("invalid source prefix")
				}
				obs.SrcPrefixLength = ptr(n)
			case 13, 30:
				if n > 128 {
					return obs, fmt.Errorf("invalid destination prefix")
				}
				obs.DstPrefixLength = ptr(n)
			case 10:
				obs.Ingress = ptr(n)
			case 14:
				obs.Egress = ptr(n)
			case 16:
				obs.SrcAS = ptr(n)
			case 17:
				obs.DstAS = ptr(n)
			case 21:
				if n > math.MaxUint32 {
					return obs, fmt.Errorf("invalid flow end uptime")
				}
				last = ptr(n)
			case 22:
				if n > math.MaxUint32 {
					return obs, fmt.Errorf("invalid flow start uptime")
				}
				first = ptr(n)
			case 32, 139:
				if n > 65535 {
					return obs, fmt.Errorf("invalid ICMP type/code")
				}
				obs.ICMPType = ptr(n >> 8)
				obs.ICMPCode = ptr(n & 255)
			case 176, 178:
				if n > 255 {
					return obs, fmt.Errorf("invalid ICMP type")
				}
				obs.ICMPType = ptr(n)
			case 177, 179:
				if n > 255 {
					return obs, fmt.Errorf("invalid ICMP code")
				}
				obs.ICMPCode = ptr(n)
			case 34, 50:
				obs.Sampling = Sampling{Status: "declared-as-reported", Interval: n, Scope: "record", Algorithm: obs.Sampling.Algorithm}
			case 35, 49:
				obs.Sampling.Algorithm = n
			case 36:
				obs.ActiveTimeout = ptr(n)
			case 37:
				obs.IdleTimeout = ptr(n)
			case 150, 151, 152, 153:
				scale := uint64(1e9)
				if f.ID >= 152 {
					scale = 1e6
				}
				if n > math.MaxInt64/scale {
					return obs, fmt.Errorf("timestamp outside nanosecond range")
				}
				value := int64(n * scale)
				if f.ID == 150 || f.ID == 152 {
					obs.StartNs = &value
				} else {
					obs.EndNs = &value
				}
				obs.TimeBasis = "exporter-absolute"
			case 158, 159:
				if n > math.MaxUint32 {
					return obs, fmt.Errorf("invalid delta timestamp")
				}
				value := exportNs - int64(n)*1000
				if f.ID == 158 {
					obs.StartNs = &value
				} else {
					obs.EndNs = &value
				}
				obs.TimeBasis = "export-time-minus-delta"
				obs.ClockUncertaintyNs = 1e9
			}
		}
	}
	if version != 10 && obs.StartNs == nil && first != nil {
		value := exportNs - int64(uptime-uint32(*first))*1e6
		obs.StartNs = &value
		obs.TimeBasis = "export-time-minus-uptime"
	}
	if version != 10 && obs.EndNs == nil && last != nil {
		value := exportNs - int64(uptime-uint32(*last))*1e6
		obs.EndNs = &value
		obs.TimeBasis = "export-time-minus-uptime"
	}
	if version == 9 && obs.TimeBasis == "export-time-minus-uptime" {
		obs.ClockUncertaintyNs = 1e9
	}
	if obs.StartNs != nil && obs.EndNs != nil && *obs.StartNs > *obs.EndNs {
		return obs, fmt.Errorf("reversed flow timestamps")
	}
	if obs.Sampling.Status == "" {
		obs.Sampling = Sampling{Status: "unknown", Scope: "unknown"}
	}
	return obs, nil
}
