package gateway

import (
	"context"
	"net"
	"strconv"
)

func dnpFunction(f byte) string {
	switch f {
	case 1:
		return "READ"
	case 2:
		return "WRITE"
	case 3:
		return "SELECT"
	case 4:
		return "OPERATE"
	case 5:
		return "DIRECT_OPERATE"
	case 6:
		return "DIRECT_OPERATE_NR"
	case 13:
		return "COLD_RESTART"
	case 14:
		return "WARM_RESTART"
	}
	return ""
}

// A small explicit object profile avoids treating an unknown value stride as
// another object header. Sizes follow IEEE 1815 and decoder/stream/dnp3/objects.
func dnpObjectSize(group, variation byte) (size, bits int) {
	switch group {
	case 1, 10:
		if variation == 1 {
			return 0, 1
		}
		if variation == 2 {
			return 1, 0
		}
	case 3:
		if variation == 1 {
			return 0, 2
		}
		if variation == 2 {
			return 1, 0
		}
	case 2, 4, 11, 13:
		switch variation {
		case 1:
			return 1, 0
		case 2:
			return 7, 0
		case 3:
			return 3, 0
		}
	case 12:
		if variation == 1 {
			return 11, 0
		}
	case 20:
		switch variation {
		case 1:
			return 5, 0
		case 2:
			return 3, 0
		case 5:
			return 4, 0
		case 6:
			return 2, 0
		}
	case 30:
		switch variation {
		case 1, 5:
			return 5, 0
		case 2:
			return 3, 0
		case 3:
			return 4, 0
		case 4:
			return 2, 0
		case 6:
			return 9, 0
		}
	case 40, 41:
		switch variation {
		case 1, 3:
			return 5, 0
		case 2:
			return 3, 0
		case 4:
			return 9, 0
		}
	case 50:
		if variation == 1 || variation == 3 {
			return 6, 0
		}
		if variation == 2 {
			return 10, 0
		}
	case 60:
		if variation >= 1 && variation <= 4 {
			return 0, 0
		}
	case 80:
		if variation == 1 {
			return 0, 1
		}
	}
	return -1, 0
}
func dnpUint(b []byte) uint64 {
	var n uint64
	for i, v := range b {
		n |= uint64(v) << uint(8*i)
	}
	return n
}
func dnpObjects(data []byte, function byte, limit int) ([]map[string]string, error) {
	if function == 13 || function == 14 {
		if len(data) != 0 {
			return nil, errFrame
		}
		return []map[string]string{{}}, nil
	}
	if len(data) == 0 {
		return nil, errFrame
	}
	var result []map[string]string
	for len(data) > 0 {
		if len(data) < 3 || len(result) >= limit {
			return nil, errFrame
		}
		group, variation, q := data[0], data[1], data[2]
		data = data[3:]
		prefix, spec := q>>4, q&15
		if prefix > 3 {
			return nil, errFrame
		}
		size, bits := dnpObjectSize(group, variation)
		if size < 0 && !(function == 1 && variation == 0 && dnpKnownGroup(group)) {
			return nil, errFrame
		}
		if function != 1 {
			if function >= 3 && function <= 6 && group != 12 && group != 41 {
				return nil, errFrame
			}
			if function == 2 && group != 12 && group != 41 && group != 50 {
				return nil, errFrame
			}
		}
		a := map[string]string{"dnp3.object_group": strconv.Itoa(int(group)), "dnp3.variation": strconv.Itoa(int(variation)), "dnp3.qualifier": strconv.Itoa(int(q))}
		var start, end, count uint64
		known := false
		switch spec {
		case 0, 1, 2:
			width := 1 << spec
			if prefix != 0 || len(data) < 2*width {
				return nil, errFrame
			}
			start, end = dnpUint(data[:width]), dnpUint(data[width:2*width])
			data = data[2*width:]
			if end < start || end-start >= 65536 {
				return nil, errFrame
			}
			count = end - start + 1
			known = true
		case 6:
			if prefix != 0 || function != 1 {
				return nil, errFrame
			}
			a["dnp3.range"] = "all"
		case 7, 8, 9:
			a["dnp3.range"] = "count"
			width := 1 << (spec - 7)
			if len(data) < width {
				return nil, errFrame
			}
			count = dnpUint(data[:width])
			data = data[width:]
			if count < 1 || count > 65536 {
				return nil, errFrame
			}
			if function == 1 && prefix != 0 {
				return nil, errFrame
			}
		default:
			return nil, errFrame
		}
		if function != 1 {
			if size < 0 || bits != 0 {
				return nil, errFrame
			}
			pre := 0
			if prefix > 0 {
				pre = 1 << (prefix - 1)
			}
			if !known && pre == 0 && (group != 50 || count != 1) {
				return nil, errFrame
			}
			if uint64(len(data)) < count*uint64(size+pre) {
				return nil, errFrame
			}
			if pre > 0 {
				start = ^uint64(0)
				end = 0
				for i := uint64(0); i < count; i++ {
					index := dnpUint(data[:pre])
					if index < start {
						start = index
					}
					if index > end {
						end = index
					}
					data = data[pre+size:]
				}
				known = true
			} else {
				data = data[int(count)*size:]
			}
		}
		if spec != 6 {
			a["dnp3.count"] = strconv.FormatUint(count, 10)
		}
		if known {
			a["dnp3.address_start"] = strconv.FormatUint(start, 10)
			a["dnp3.address_end"] = strconv.FormatUint(end, 10)
			a["dnp3.range"] = "indexed"
		}
		result = append(result, a)
	}
	return result, nil
}
func dnpKnownGroup(g byte) bool {
	switch g {
	case 1, 2, 3, 4, 10, 11, 12, 13, 20, 30, 40, 41, 50, 60, 80:
		return true
	}
	return false
}

func (g *Gateway) dnpACK(ctx context.Context, c net.Conn, master, out uint16) error {
	f, err := g.readDNP(ctx, c, false)
	if err != nil {
		return err
	}
	if f.control != 0 || f.source != out || f.destination != master || len(f.data) != 0 {
		return errFrame
	}
	return nil
}
func (g *Gateway) dnp3Client(ctx context.Context, c net.Conn, ip string) {
	client := dnpLink{g: g, c: c, fromMaster: true}
	var up net.Conn
	var origin dnpLink
	initialized, fcb := false, true
	var nextApplication byte
	applicationSeen := false
	for i := 0; i < g.cfg.MaxSessionMessages; i++ {
		// One complete train, including link/application negotiation, has one timeout.
		// The first byte still gets the configured idle budget.
		requestCtx, cancel := context.WithTimeout(ctx, g.cfg.IdleTimeout)
		apps, _, err := client.message(requestCtx, true)
		cancel()
		if err != nil {
			return
		}
		function := apps[0].function
		if applicationSeen && apps[0].control&15 != nextApplication {
			return
		}
		nextApplication = (apps[0].control + 1) & 15
		applicationSeen = true
		name := dnpFunction(function)
		if name == "" {
			return
		}
		var metadata []map[string]string
		// Objects may span transport segments, not application APDUs. Parsing a
		// concatenation could classify different objects than an outstation sees.
		for _, app := range apps {
			part, parseErr := dnpObjects(app.objects, function, g.cfg.MaxStateEntries-len(metadata))
			if parseErr != nil {
				return
			}
			metadata = append(metadata, part...)
		}
		for _, a := range metadata {
			a["dnp3.function"] = strconv.Itoa(int(function))
			a["dnp3.source"] = strconv.Itoa(int(client.master))
			a["dnp3.destination"] = strconv.Itoa(int(client.outstation))
			if !g.allowed(event("dnp3", name, ip, a)) {
				return
			}
		}
		if up == nil {
			up, err = g.dial(ctx)
			if err != nil {
				return
			}
			defer up.Close()
			stop := context.AfterFunc(ctx, func() { up.Close() })
			defer stop()
			origin = dnpLink{g: g, c: up, master: client.master, outstation: client.outstation, bound: true}
		}
		exchangeCtx, done := context.WithTimeout(ctx, g.cfg.IOTimeout)
		for _, app := range apps {
			for _, f := range app.frames {
				if f.control&15 == 3 {
					if !initialized {
						reset := dnpFrame{control: 0xc0, source: client.master, destination: client.outstation}
						if g.writeFrame(exchangeCtx, up, reset.wire()) != nil || g.dnpACK(exchangeCtx, up, client.master, client.outstation) != nil {
							done()
							return
						}
						initialized = true
					}
					f.control = 0xd3
					if fcb {
						f.control |= 0x20
					}
					fcb = !fcb
				}
				if g.writeFrame(exchangeCtx, up, f.wire()) != nil {
					done()
					return
				}
				if f.control&15 == 3 && g.dnpACK(exchangeCtx, up, client.master, client.outstation) != nil {
					done()
					return
				}
			}
			if app.control&0x20 != 0 {
				budget, frames := 0, 0
				confirmation, e := origin.application(exchangeCtx, false, &budget, &frames)
				if e != nil || confirmation.function != 0 || confirmation.control != 0xc0|app.control&15 || len(confirmation.objects) != 0 {
					done()
					return
				}
				origin.busy = false
			}
		}
		if function == 6 {
			done()
			continue
		}
		responses, _, err := origin.message(exchangeCtx, false)
		done()
		if err != nil {
			return
		}
		if responses[0].function != 129 || responses[0].control&15 != apps[len(apps)-1].control&15 {
			return
		}
		// Link and CON termination are independent on the two legs. Responses retain
		// address direction and application payload; rewritten controls get new CRCs.
		for _, response := range responses {
			first := true
			for _, f := range response.frames {
				f.control = 0x44
				f.data = append([]byte(nil), f.data...)
				if first {
					f.data[1] &^= 0x20
					first = false
				}
				if g.writeFrame(ctx, c, f.wire()) != nil {
					return
				}
			}
		}
	}
}
