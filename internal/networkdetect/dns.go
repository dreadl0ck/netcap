package networkdetect

import (
	"encoding/hex"
	"strings"

	"golang.org/x/net/publicsuffix"
)

func dnsTunnelPayload(name string, qtype uint16) (payload, zone string, suspicious bool) {
	if qtype != 1 && qtype != 5 && qtype != 15 && qtype != 16 && qtype != 28 {
		return
	}
	labels := strings.Split(name, ".")
	if len(labels) < 3 {
		return
	}
	zone, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		zone = strings.Join(labels[len(labels)-2:], ".")
	}
	prefix := strings.TrimSuffix(name, "."+zone)
	if prefix == name {
		return "", "", false
	}
	parts := strings.Split(prefix, ".")
	if parts[0] == "dnscat" {
		parts = parts[1:]
	}
	encoded := strings.Join(parts, "")
	if len(encoded) >= 24 && len(encoded)%2 == 0 {
		if raw, err := hex.DecodeString(encoded); err == nil && len(raw) >= 5 && raw[2] <= 4 && entropy([]byte(encoded)) >= 2.5 {
			return encoded, zone, true
		}
	}
	// Preserve the generic TXT heuristic, grouping all encoded labels under
	// the stable registrable zone rather than under another variable label.
	if qtype == 16 && len(parts) > 0 && len(parts[0]) >= 24 && entropy([]byte(parts[0])) >= 3.5 {
		return encoded, zone, true
	}
	return "", "", false
}
