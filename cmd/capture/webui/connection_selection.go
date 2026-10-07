package webui

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/gopacket/gopacket"
)

type connectionPacketSelection struct {
	bpf        string
	start, end *int64
}

func parseConnectionPacketSelection(query url.Values) (connectionPacketSelection, error) {
	var selection connectionPacketSelection
	src, err := netip.ParseAddr(query.Get("srcIP"))
	if err != nil || src.Zone() != "" {
		return selection, fmt.Errorf("invalid source IP")
	}
	dst, err := netip.ParseAddr(query.Get("dstIP"))
	if err != nil || dst.Zone() != "" || src.Is4() != dst.Is4() {
		return selection, fmt.Errorf("invalid destination IP or address family")
	}
	srcPort, err := strconv.ParseUint(query.Get("srcPort"), 10, 16)
	if err != nil {
		return selection, fmt.Errorf("invalid source port")
	}
	dstPort, err := strconv.ParseUint(query.Get("dstPort"), 10, 16)
	if err != nil {
		return selection, fmt.Errorf("invalid destination port")
	}
	protocol := strings.ToLower(query.Get("protocol"))
	if protocol != "tcp" && protocol != "udp" {
		return selection, fmt.Errorf("protocol must be TCP or UDP")
	}
	family := "ip"
	if src.Is6() {
		family = "ip6"
	}
	selection.bpf = fmt.Sprintf("%s and %s and ((src host %s and src port %d and dst host %s and dst port %d) or (src host %s and src port %d and dst host %s and dst port %d))",
		family, protocol, src, srcPort, dst, dstPort, dst, dstPort, src, srcPort)
	if query.Has("startNs") != query.Has("endNs") {
		return selection, fmt.Errorf("startNs and endNs must be supplied together")
	}
	if query.Has("startNs") {
		start, err := strconv.ParseInt(query.Get("startNs"), 10, 64)
		if err != nil {
			return selection, fmt.Errorf("invalid startNs")
		}
		end, err := strconv.ParseInt(query.Get("endNs"), 10, 64)
		if err != nil || end < start {
			return selection, fmt.Errorf("invalid endNs or reversed time range")
		}
		selection.start, selection.end = &start, &end
	}
	return selection, nil
}

func (s connectionPacketSelection) contains(ci gopacket.CaptureInfo) bool {
	return s.start == nil || (ci.Timestamp.UnixNano() >= *s.start && ci.Timestamp.UnixNano() <= *s.end)
}
