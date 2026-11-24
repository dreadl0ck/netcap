package types

import (
	"crypto/md5" // JA3 specifies MD5 as a fingerprint, not for integrity.
	"encoding/hex"
	"strconv"
)

// ClientHelloJA3 computes the JA3 fingerprint from the legacy version and
// lists in wire order. It also works on ClientHellos stored before Ja3 existed.
func ClientHelloJA3(version int32, ciphers, extensions, groups, points []int32) string {
	if version < 0x0300 || version > 0x0303 || len(ciphers) == 0 {
		return ""
	}
	wire := strconv.AppendInt(nil, int64(version), 10)
	for i, values := range [4][]int32{ciphers, extensions, groups, points} {
		wire = append(wire, ',')
		first := true
		for _, v := range values {
			if i < 3 && v&0x0f0f == 0x0a0a && v>>8 == v&0xff {
				continue
			}
			if !first {
				wire = append(wire, '-')
			}
			first = false
			wire = strconv.AppendInt(wire, int64(v), 10)
		}
	}
	digest := md5.Sum(wire)
	return hex.EncodeToString(digest[:])
}

// ServerHelloJA3 computes JA3S from the legacy version, cipher and wire-ordered extensions.
func ServerHelloJA3(version, cipher int32, extensions []int32) string {
	if version < 0x0300 || version > 0x0303 {
		return ""
	}
	wire := strconv.AppendInt(nil, int64(version), 10)
	wire = strconv.AppendInt(append(wire, ','), int64(cipher), 10)
	wire = append(wire, ',')
	first := true
	for _, v := range extensions {
		if v&0x0f0f == 0x0a0a && v>>8 == v&0xff {
			continue
		}
		if !first {
			wire = append(wire, '-')
		}
		first = false
		wire = strconv.AppendInt(wire, int64(v), 10)
	}
	digest := md5.Sum(wire)
	return hex.EncodeToString(digest[:])
}
