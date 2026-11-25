package rules

import (
	"bytes"
	"regexp"
	"slices"
	"strings"
)

const packetServiceGate = " && ACK && PayloadSize > 0"
const flowServiceGate = ` && TransportProto == "TCP" && (TCPInitiatorObserved || CounterSemantics == "") && (Established || (PacketsClientToServer > 0 && PacketsServerToClient > 0 && (AppPayloadSize64 > 0 || AppPayloadSize > 0)))`
const initiatedServiceGate = "TCPInitiatorObserved && Established && "

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
		if r == nil || !slices.Equal(r.DedupeBy, packetServiceKey) {
			continue
		}
		if r.Type == "Connection" && strings.HasPrefix(r.Expression, initiatedServiceGate) {
			r.DedupeBy = slices.Clone(flowServiceKey)
		} else if predicate, ok := strings.CutSuffix(r.Expression, packetServiceGate); r.Type == "TCP" && ok && servicePort.MatchString(predicate) {
			r.Type = "Connection"
			r.Expression = servicePort.ReplaceAllString(predicate, "ParsePort(DstPort)") + flowServiceGate
			r.DedupeBy = slices.Clone(flowServiceKey)
		}
	}
}

func isSavedPacketServiceRule(base, saved *Rule) bool {
	if base.Type != "Connection" || !slices.Equal(base.DedupeBy, flowServiceKey) {
		return false
	}
	old := *base
	old.DedupeBy = packetServiceKey
	if saved.Type == "Connection" && strings.HasPrefix(base.Expression, initiatedServiceGate) {
		return bytes.Equal(legacyComparable(&old), legacyComparable(saved))
	}
	predicate, ok := strings.CutSuffix(base.Expression, flowServiceGate)
	if !ok || saved.Type != "TCP" {
		return false
	}
	old.Type, old.Expression = "TCP", flowPort.ReplaceAllString(predicate, "DstPort")+packetServiceGate
	return bytes.Equal(legacyComparable(&old), legacyComparable(saved))
}
