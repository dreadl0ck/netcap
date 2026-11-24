package rules

import (
	"bytes"
	"regexp"
	"slices"
	"strings"
)

const packetServiceGate = " && ACK && PayloadSize > 0"
const flowServiceGate = ` && TransportProto == "TCP" && (Established || (PacketsClientToServer > 0 && PacketsServerToClient > 0 && (AppPayloadSize64 > 0 || AppPayloadSize > 0)))`

var (
	packetServiceKey = []string{"SrcIP", "DstIP", "DstPort"}
	flowServiceKey   = []string{"SrcIP", "SrcPort", "DstIP", "DstPort", "TimestampFirst"}
	servicePort      = regexp.MustCompile(`\bDstPort\b`)
	flowPort         = regexp.MustCompile(`\bParsePort\(DstPort\)`)
)

func (c *Config) useServiceFlows() {
	if !c.ConnectionPortGates {
		return
	}
	for _, r := range c.Rules {
		if r == nil || r.Type != "TCP" || !slices.Equal(r.DedupeBy, packetServiceKey) {
			continue
		}
		if predicate, ok := strings.CutSuffix(r.Expression, packetServiceGate); ok && servicePort.MatchString(predicate) {
			r.Type = "Connection"
			r.Expression = servicePort.ReplaceAllString(predicate, "ParsePort(DstPort)") + flowServiceGate
			r.DedupeBy = slices.Clone(flowServiceKey)
		}
	}
}

func isSavedPacketServiceRule(base, saved *Rule) bool {
	predicate, ok := strings.CutSuffix(base.Expression, flowServiceGate)
	if !ok || base.Type != "Connection" || saved.Type != "TCP" || !slices.Equal(base.DedupeBy, flowServiceKey) {
		return false
	}
	old := *base
	old.Type, old.Expression, old.DedupeBy = "TCP", flowPort.ReplaceAllString(predicate, "DstPort")+packetServiceGate, packetServiceKey
	return bytes.Equal(legacyComparable(&old), legacyComparable(saved))
}
