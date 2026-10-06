package behavior

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

// RecordContext supplements immutable early evidence; legacy audit records lack network scope.
type RecordContext struct {
	Type           string `json:"type"`
	Index          int    `json:"index"`
	SHA256         string `json:"sha256"`
	FirstSeen      int64  `json:"firstSeen"`
	LastSeen       int64  `json:"lastSeen"`
	CaptureLagNS   int64  `json:"captureLagNS"`
	ScopeAvailable bool   `json:"scopeAvailable"`
	Outcome        string `json:"outcome"`
	Authentication string `json:"authentication"`
	Command        int32  `json:"command,omitempty"`
	Status         uint32 `json:"status,omitempty"`
	Response       bool   `json:"response,omitempty"`
	Encrypted      bool   `json:"encrypted,omitempty"`
}

// MatchLateralRecord returns a tuple/time candidate, never a scope-qualified attribution.
func MatchLateralRecord(e Evidence, alertNS int64, record proto.Message, index int) *RecordContext {
	if !strings.HasPrefix(e.Detector, "lateral.") || alertNS <= 0 || e.WindowNS <= 0 || e.WindowNS > int64(24*time.Hour) || index < 0 {
		return nil
	}
	var src, dst, srcPort string
	var port uint16
	context := RecordContext{Index: index, Authentication: "unavailable"}
	switch r := record.(type) {
	case *types.Connection:
		if r == nil || strings.ToLower(r.TransportProto) != "tcp" || r.TimestampFirst <= 0 || r.TimestampLast < r.TimestampFirst {
			return nil
		}
		p, err := strconv.ParseUint(r.DstPort, 10, 16)
		if err != nil {
			return nil
		}
		src, dst, srcPort, port = r.SrcIP, r.DstIP, r.SrcPort, uint16(p)
		context.Type, context.FirstSeen, context.LastSeen = "Connection", r.TimestampFirst, r.TimestampLast
		context.Outcome = "transport outcome unavailable"
		switch {
		case r.NumRSTFlags > 0:
			context.Outcome = "TCP reset observed"
		case r.NumFINFlags > 0:
			context.Outcome = "TCP FIN observed"
		case r.SynAckTimestamp > 0:
			context.Outcome = "TCP SYN-ACK observed"
		case r.PacketsServerToClient == 0:
			context.Outcome = "no server packets observed; incomplete visibility possible"
		}
	case *types.SMB:
		if r == nil || r.Timestamp <= 0 || r.SrcPort <= 0 || r.SrcPort > 65535 || r.DstPort <= 0 || r.DstPort > 65535 {
			return nil
		}
		src, dst, srcPort, port = r.SrcIP, r.DstIP, strconv.Itoa(int(r.SrcPort)), uint16(r.DstPort)
		if r.IsResponse {
			src, dst, srcPort, port = r.DstIP, r.SrcIP, strconv.Itoa(int(r.DstPort)), uint16(r.SrcPort)
		}
		context.Type, context.FirstSeen, context.LastSeen = "SMB", r.Timestamp, r.Timestamp
		context.Command, context.Status, context.Response, context.Encrypted = r.Command, r.Status, r.IsResponse, r.IsEncrypted
		context.Outcome = "SMB request observed"
		if r.IsResponse {
			context.Outcome = "SMB response observed; status is command-specific"
		}
		if !r.IsEncrypted && (r.AuthStatus == "SUCCESS" || r.AuthStatus == "FAILED" || r.AuthStatus == "IN_PROGRESS") {
			context.Authentication = r.AuthStatus
		}
	default:
		return nil
	}
	matched := false
	// A source port narrows candidates but cannot recover omitted sensor/VLAN metadata.
	facts := append([]Fact{e.Observed}, e.Related...)
	for _, fact := range facts {
		if fact.Kind != "service" || fact.Protocol != "tcp" || fact.SrcIP != src || fact.DstIP != dst || fact.Port != port {
			continue
		}
		if fact.Token != "" && strings.SplitN(fact.Token, ":", 2)[0] != srcPort {
			continue
		}
		// Connections may close long after the decisive SYN; SMB messages are bounded by the correlation window.
		if context.FirstSeen < alertNS-e.WindowNS || (context.Type == "Connection" && context.FirstSeen > alertNS) || (context.Type == "SMB" && context.FirstSeen-alertNS > e.WindowNS) {
			continue
		}
		matched = true
		break
	}
	if !matched {
		return nil
	}
	data, err := proto.Marshal(record)
	if err != nil {
		return nil
	}
	hash := sha256.Sum256(data)
	context.SHA256 = hex.EncodeToString(hash[:])
	if context.LastSeen > alertNS {
		context.CaptureLagNS = context.LastSeen - alertNS
	}
	return &context
}
