package flowexport

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type cursor struct{ data []byte }

func (c *cursor) take(n int) ([]byte, error) {
	if n < 0 || n > len(c.data) {
		return nil, fmt.Errorf("truncated sFlow field")
	}
	v := c.data[:n]
	c.data = c.data[n:]
	return v, nil
}
func (c *cursor) word() (uint32, error) {
	v, err := c.take(4)
	if err != nil {
		return 0, err
	}
	return u32(v), nil
}
func (c *cursor) block() (uint32, []byte, error) {
	kind, err := c.word()
	if err != nil {
		return 0, nil, err
	}
	n, err := c.word()
	if err != nil {
		return 0, nil, err
	}
	if uint64(n) > uint64(len(c.data)) {
		return 0, nil, fmt.Errorf("truncated sFlow block")
	}
	v, err := c.take(int(n))
	if err != nil {
		return 0, nil, err
	}
	padding := (4 - int(n)%4) % 4
	if _, err := c.take(padding); err != nil {
		return 0, nil, err
	}
	return kind, v, nil
}
func (c *cursor) address() (string, error) {
	kind, err := c.word()
	if err != nil {
		return "", err
	}
	n := 4
	if kind == 2 {
		n = 16
	} else if kind != 1 {
		return "", fmt.Errorf("invalid sFlow address type")
	}
	v, err := c.take(n)
	if err != nil {
		return "", err
	}
	addr, ok := netip.AddrFromSlice(v)
	if !ok {
		return "", fmt.Errorf("invalid sFlow address")
	}
	return addr.String(), nil
}

func (e *Engine) decodeSFlow(data []byte, env Envelope) (Batch, error) {
	batch := Batch{Observations: []Observation{}, Issues: []Issue{}}
	fail := func(err error) (Batch, error) {
		e.health.Malformed++
		return Batch{Issues: batch.Issues, Observations: []Observation{}}, err
	}
	c := cursor{data: data[4:]}
	agent, err := c.address()
	if err != nil {
		return fail(err)
	}
	domain, err := c.word()
	if err != nil {
		return fail(err)
	}
	seq, err := c.word()
	if err != nil {
		return fail(err)
	}
	_, err = c.word()
	if err != nil {
		return fail(err)
	}
	count, err := c.word()
	if err != nil || count > 4096 {
		return fail(fmt.Errorf("invalid sFlow sample count"))
	}
	key := scope{env.Exporter, env.Collector, 5005, domain}
	state := e.domains[key]
	digest := sha256.Sum256(data)
	if state != nil && state.sequence == seq && state.lastDigest == digest {
		e.health.Duplicates++
		return batch, nil
	}
	if state == nil && len(e.domains) >= e.config.MaxDomains {
		e.health.StateLimitExceeded++
		return batch, fmt.Errorf("exporter domain limit exceeded")
	}
	if state != nil && state.expected != seq {
		e.health.SequenceDiscontinuities++
		batch.Issues = append(batch.Issues, Issue{Code: "sequence-discontinuity", Envelope: env, Detail: fmt.Sprintf("sFlow expected %d, observed %d", state.expected, seq)})
	}
	for i := uint32(0); i < count; i++ {
		kind, body, err := c.block()
		if err != nil {
			return fail(err)
		}
		if kind>>12 != 0 || (kind&4095 != 1 && kind&4095 != 3) {
			batch.Issues = append(batch.Issues, Issue{Code: "non-flow-sample", Envelope: env, Detail: fmt.Sprintf("sFlow sample format %d retained in original datagram", kind)})
			continue
		}
		obs, issues, err := decodeSFlowSample(body, kind&4095 == 3, env, domain, seq, int(i))
		if err != nil {
			return fail(err)
		}
		obs.Limitations = append(obs.Limitations, "reported agent "+agent+" is separate from transport exporter identity")
		batch.Observations = append(batch.Observations, obs)
		batch.Issues = append(batch.Issues, issues...)
	}
	if len(c.data) != 0 {
		return fail(fmt.Errorf("trailing sFlow datagram bytes"))
	}
	e.domains[key] = &domainState{sequence: seq, expected: seq + 1, hasSequence: true, expectedKnown: true, lastDigest: digest, seen: env.ReceivedNs, templates: map[uint16]template{}}
	for i := range batch.Observations {
		obs := &batch.Observations[i]
		identity := sha256.Sum256([]byte(fmt.Sprintf("%s/%s/%d/%x/%d/%d", env.Exporter, env.Collector, env.ReceivedNs, digest, env.PacketOrdinal, i)))
		obs.ID = hex.EncodeToString(identity[:])
	}
	e.health.Records += uint64(len(batch.Observations))
	return batch, nil
}

func decodeSFlowSample(data []byte, expanded bool, env Envelope, domain, seq uint32, ordinal int) (Observation, []Issue, error) {
	obs := Observation{Version: 1, Envelope: env, Format: "sflow-v5", Domain: domain, Sequence: seq, RecordOrdinal: ordinal, CounterSemantics: "sampled-packet-as-reported", TimeBasis: "collector-receive-time-not-flow-time", Fields: []Field{}, Limitations: []string{"sampled observation; short traffic may be entirely absent", "frame/IP length depends on sample record format", "no automatic sampling expansion", "sampled headers are not full capture evidence"}}
	var issues []Issue
	c := cursor{data: data}
	_, err := c.word()
	if err != nil {
		return obs, issues, err
	}
	if _, err := c.word(); err != nil {
		return obs, issues, err
	}
	if expanded {
		if _, err := c.word(); err != nil {
			return obs, issues, err
		}
	}
	rate, err := c.word()
	if err != nil {
		return obs, issues, err
	}
	obs.Sampling = Sampling{Status: "declared-as-reported", Interval: uint64(rate), Scope: "sample"}
	if _, err := c.word(); err != nil {
		return obs, issues, err
	}
	drops, err := c.word()
	if err != nil {
		return obs, issues, err
	}
	if drops > 0 {
		issues = append(issues, Issue{Code: "sampler-reported-drops", Envelope: env, Detail: fmt.Sprintf("sFlow sample drops %d", drops)})
	}
	for i := 0; i < 2; i++ {
		format := uint32(0)
		value, err := c.word()
		if err != nil {
			return obs, issues, err
		}
		if expanded {
			format = value
			value, err = c.word()
			if err != nil {
				return obs, issues, err
			}
		} else {
			format = value >> 30
			value &= 0x3fffffff
		}
		if format == 0 {
			if i == 0 {
				obs.Ingress = ptr(uint64(value))
			} else {
				obs.Egress = ptr(uint64(value))
			}
		} else {
			obs.Limitations = append(obs.Limitations, fmt.Sprintf("interface %d uses format %d, not a single ifIndex", i, format))
		}
	}
	count, err := c.word()
	if err != nil || count > 4096 {
		return obs, issues, fmt.Errorf("invalid sFlow record count")
	}
	packetSeen := false
	for i := uint32(0); i < count; i++ {
		kind, body, err := c.block()
		if err != nil {
			return obs, issues, err
		}
		obs.Fields = append(obs.Fields, Field{ID: uint16(kind & 4095), Enterprise: kind >> 12, EnterpriseProvided: kind>>12 != 0, Value: append([]byte(nil), body...)})
		if kind>>12 != 0 {
			continue
		}
		if kind == 1 || kind == 3 || kind == 4 {
			if packetSeen {
				return obs, issues, fmt.Errorf("multiple packet records in one sFlow sample")
			}
			packetSeen = true
			if err := sflowPacket(&obs, kind, body); err != nil {
				return obs, issues, err
			}
		} else if kind == 1002 {
			r := cursor{data: body}
			obs.NextHop, err = r.address()
			if err != nil {
				return obs, issues, err
			}
			src, err := r.word()
			if err != nil {
				return obs, issues, err
			}
			dst, err := r.word()
			if err != nil {
				return obs, issues, err
			}
			obs.SrcPrefixLength = ptr(uint64(src))
			obs.DstPrefixLength = ptr(uint64(dst))
			if len(r.data) != 0 {
				return obs, issues, fmt.Errorf("trailing extended router bytes")
			}
		}
	}
	if len(c.data) != 0 {
		return obs, issues, fmt.Errorf("trailing sFlow sample bytes")
	}
	if !packetSeen {
		obs.Limitations = append(obs.Limitations, "sample has no supported packet record")
	}
	return obs, issues, nil
}

func sflowPacket(obs *Observation, kind uint32, data []byte) error {
	obs.Packets = ptr(1)
	if kind == 3 || kind == 4 {
		want := 32
		if kind == 4 {
			want = 56
		}
		if len(data) != want {
			return fmt.Errorf("invalid sFlow sampled IP record length")
		}
		obs.Bytes = ptr(uint64(u32(data)))
		obs.Protocol = ptr(uint64(u32(data[4:])))
		n := 4
		if kind == 4 {
			n = 16
		}
		src, _ := netip.AddrFromSlice(data[8 : 8+n])
		dst, _ := netip.AddrFromSlice(data[8+n : 8+2*n])
		obs.SrcIP, obs.DstIP = src.String(), dst.String()
		offset := 8 + 2*n
		sp, dp, flags := u32(data[offset:]), u32(data[offset+4:]), u32(data[offset+8:])
		if sp > 65535 || dp > 65535 || *obs.Protocol > 255 {
			return fmt.Errorf("invalid sampled IP ports/protocol")
		}
		obs.SrcPort, obs.DstPort = ptr(uint64(sp)), ptr(uint64(dp))
		obs.TCPFlags = ptr(uint64(flags))
		return nil
	}
	if len(data) < 16 {
		return fmt.Errorf("truncated sFlow raw header")
	}
	protocol, length, headerSize := u32(data), u32(data[4:]), u32(data[12:])
	if int(headerSize) > len(data)-16 || len(data)-16-int(headerSize) > 3 || !zero(data[16+int(headerSize):]) {
		return fmt.Errorf("invalid sampled header length")
	}
	var base gopacket.LayerType
	switch protocol {
	case 1:
		base = layers.LayerTypeEthernet
	case 11:
		base = layers.LayerTypeIPv4
	case 12:
		base = layers.LayerTypeIPv6
	default:
		obs.Limitations = append(obs.Limitations, "unsupported sampled header protocol")
		return nil
	}
	packet := gopacket.NewPacket(data[16:16+int(headerSize)], base, gopacket.Default)
	obs.Bytes = ptr(uint64(length))
	if network := packet.NetworkLayer(); network != nil {
		obs.SrcIP, obs.DstIP = network.NetworkFlow().Src().String(), network.NetworkFlow().Dst().String()
	}
	if ip, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
		obs.Protocol = ptr(uint64(ip.Protocol))
	}
	if ip, ok := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
		obs.Protocol = ptr(uint64(ip.NextHeader))
	}
	if tcp, ok := packet.TransportLayer().(*layers.TCP); ok {
		obs.Protocol = ptr(6)
		obs.SrcPort, obs.DstPort = ptr(uint64(tcp.SrcPort)), ptr(uint64(tcp.DstPort))
		var flags uint64
		if tcp.FIN {
			flags |= 1
		}
		if tcp.SYN {
			flags |= 2
		}
		if tcp.RST {
			flags |= 4
		}
		if tcp.PSH {
			flags |= 8
		}
		if tcp.ACK {
			flags |= 16
		}
		if tcp.URG {
			flags |= 32
		}
		if tcp.ECE {
			flags |= 64
		}
		if tcp.CWR {
			flags |= 128
		}
		obs.TCPFlags = ptr(flags)
	}
	if udp, ok := packet.TransportLayer().(*layers.UDP); ok {
		obs.Protocol = ptr(17)
		obs.SrcPort, obs.DstPort = ptr(uint64(udp.SrcPort)), ptr(uint64(udp.DstPort))
	}
	if packet.ErrorLayer() != nil || headerSize < length {
		obs.Limitations = append(obs.Limitations, "sampled header is truncated or incompletely decoded")
	}
	return nil
}
