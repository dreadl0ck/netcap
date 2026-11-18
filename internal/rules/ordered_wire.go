package rules

import (
	"bytes"
	"slices"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"google.golang.org/protobuf/encoding/protowire"
)

// Field numbers come from types/netcap.proto. Generated encoders write each
// map as a contiguous run; repeated non-map fields keep their original order.
func orderRuleRecordMaps(message proto.Message, wire []byte) error {
	switch message.(type) {
	case *types.LinkFrame:
		return orderWireMaps(wire, 0, 9)
	case *types.HTTP:
		return orderWireMaps(wire, 0, 26, 27, 28)
	case *types.USB:
		return orderWireMaps(wire, 0, 21)
	case *types.Host:
		return orderWireMaps(wire, 0, 9, 11)
	case *types.Mail:
		return orderWireMaps(wire, 16)
	case *types.Syslog:
		return orderWireMaps(wire, 19)
	case *types.QUICClientHello:
		return orderWireMaps(wire, 0, 19)
	case *types.Protobuf:
		return orderWireMaps(wire, 0, 10, 19, 20)
	default:
		return nil
	}
}

func orderWireMaps(wire []byte, nested protowire.Number, maps ...protowire.Number) error {
	for len(wire) > 0 {
		num, typ, n := protowire.ConsumeField(wire)
		if n < 0 {
			return protowire.ParseError(n)
		}
		if typ == protowire.BytesType && num == nested {
			_, _, tagLen := protowire.ConsumeTag(wire)
			body, _ := protowire.ConsumeBytes(wire[tagLen:n])
			if err := orderWireMaps(body, 0, 2); err != nil {
				return err
			}
		}
		if typ != protowire.BytesType || !slices.Contains(maps, num) {
			wire = wire[n:]
			continue
		}
		var entries [][]byte
		end := n
		for end < len(wire) {
			next, typ, tagLen := protowire.ConsumeTag(wire[end:])
			if next != num || typ != protowire.BytesType || tagLen < 0 {
				break
			}
			_, size := protowire.ConsumeBytes(wire[end+tagLen:])
			if size < 0 {
				return protowire.ParseError(size)
			}
			if entries == nil {
				entries = append(entries, wire[:n])
			}
			last := end + tagLen + size
			entries = append(entries, wire[end:last])
			end = last
		}
		if len(entries) > 1 && !slices.IsSortedFunc(entries, bytes.Compare) {
			slices.SortFunc(entries, bytes.Compare)
			sorted := make([]byte, 0, end)
			for _, entry := range entries {
				sorted = append(sorted, entry...)
			}
			copy(wire, sorted)
		}
		wire = wire[end:]
	}
	return nil
}
