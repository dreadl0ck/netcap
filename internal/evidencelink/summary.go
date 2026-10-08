/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package evidencelink

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/dreadl0ck/netcap/types"
)

// summaryFields names the JSON fields shown for each record type, in order.
// Only strings, integers and booleans are rendered; other values are skipped.
var summaryFields = map[string][]string{
	"Connection":     {"SrcIP", "SrcPort", "DstIP", "DstPort", "TransportProto", "ApplicationProto", "TotalSize", "NumPackets"},
	"DNS":            {"TransactionStatus", "RTT", "ResponseCode"},
	"HTTP":           {"Method", "Host", "URL", "StatusCode", "UserAgent"},
	"TLSClientHello": {"SNI", "Ja4"},
	"TLSServerHello": {"AlpnProtocol", "Ja4s"},
	"SSH":            {"SoftwareVersion", "Ja4ssh", "IsClient"},
	"File":           {"Name", "Length", "ContentType", "Source"},
	"DCERPC":         {"PacketTypeName", "InterfaceName", "OperationName"},
	"Alert":          {"RuleName", "Severity", "RecordType"},
}

// Summarize renders the identifying fields of a record for display.
func Summarize(typ string, record any) []Field {
	var fields []Field
	if dns, ok := record.(*types.DNS); ok {
		if len(dns.Questions) > 0 && dns.Questions[0] != nil && dns.Questions[0].Name != "" {
			fields = append(fields, Field{Name: "Query", Value: dns.Questions[0].Name})
		}
		if dns.QR {
			var ips []string
			for _, answer := range dns.Answers {
				if answer != nil && (answer.Type == 1 || answer.Type == 28) && answer.IP != "" && answer.IP != "<nil>" {
					ips = append(ips, answer.IP)
				}
			}
			if len(ips) > 0 {
				fields = append(fields, Field{Name: "Answers", Value: strings.Join(ips, ",")})
			}
		}
	}
	names := summaryFields[typ]
	if len(names) == 0 {
		return fields
	}
	data, err := json.Marshal(record)
	if err != nil {
		return fields
	}
	var values map[string]json.RawMessage
	if json.Unmarshal(data, &values) != nil {
		return fields
	}
	for _, name := range names {
		if value, ok := scalar(values[name]); ok {
			fields = append(fields, Field{Name: name, Value: value})
		}
	}
	return fields
}

func scalar(raw json.RawMessage) (string, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return "", false
	}
	switch raw[0] {
	case '"':
		var s string
		if json.Unmarshal(raw, &s) != nil || s == "" {
			return "", false
		}
		return s, true
	case 't', 'f':
		return string(raw), true
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		if bytes.ContainsAny(raw, ".eE") {
			return "", false
		}
		return string(raw), true
	}
	return "", false
}
