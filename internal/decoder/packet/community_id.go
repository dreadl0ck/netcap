package packet

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"net"
)

// Portless IP protocols omit the four port octets from the v1 hash input.
func portlessCommunityID(src, dst net.IP, protocol byte) string {
	if v4 := src.To4(); v4 != nil {
		src = v4
	} else {
		src = src.To16()
	}
	if v4 := dst.To4(); v4 != nil {
		dst = v4
	} else {
		dst = dst.To16()
	}
	if len(src) == 0 || len(src) != len(dst) {
		return ""
	}
	if bytes.Compare(src, dst) > 0 {
		src, dst = dst, src
	}
	data := binary.BigEndian.AppendUint16(nil, communityIDGenerator.Seed)
	data = append(data, src...)
	data = append(data, dst...)
	data = append(data, protocol, 0)
	sum := sha1.Sum(data)
	return "1:" + base64.StdEncoding.EncodeToString(sum[:])
}
