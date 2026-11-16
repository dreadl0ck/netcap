package packetmeta

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
)

func appendBytes(out, data []byte) []byte {
	out = binary.AppendUvarint(out, uint64(len(data)))
	return append(out, data...)
}
func appendTime(out []byte, t time.Time) []byte {
	if t.IsZero() {
		out = append(out, 0)
		return out
	}
	out = append(out, 1)
	out = binary.AppendVarint(out, t.Unix())
	return binary.AppendUvarint(out, uint64(t.Nanosecond()))
}

func Marshal(ci gopacket.CaptureInfo) ([]byte, error) {
	c := Save(ci)
	var flags byte
	if c.MissingTime {
		flags |= 1
	}
	if c.FCS.Known {
		flags |= 2
	}
	if c.FCS.Present {
		flags |= 4
	}
	if c.Context != nil {
		flags |= 8
	}
	out := appendTime([]byte{1, flags}, c.Timestamp)
	if c.Context != nil && len(c.Context.LinkTransformations) != 0 {
		out[0] = 2
	}
	for _, n := range []int{c.CaptureLength, c.Length, c.Interface, c.LogicalInterface} {
		out = binary.AppendVarint(out, int64(n))
	}
	if c.Context == nil {
		return out, nil
	}
	out = appendBytes(out, []byte(c.Context.Scope))
	out = appendBytes(out, []byte(c.Context.Status))
	flags = 0
	if c.Context.Reassembled {
		flags |= 1
	}
	if c.Context.SyntheticNetwork {
		flags |= 2
	}
	out = append(out, flags)
	out = appendTime(out, c.Context.CompletedAt)
	out = binary.AppendUvarint(out, uint64(len(c.Context.Tunnels)))
	for _, tunnel := range c.Context.Tunnels {
		wire, err := proto.Marshal(tunnel)
		if err != nil {
			return nil, err
		}
		out = appendBytes(out, wire)
	}
	out = binary.AppendUvarint(out, uint64(len(c.Context.Packets)))
	for _, packet := range c.Context.Packets {
		wire, err := proto.Marshal(packet)
		if err != nil {
			return nil, err
		}
		out = appendBytes(out, wire)
	}
	if out[0] == 2 {
		out = binary.AppendUvarint(out, uint64(len(c.Context.LinkTransformations)))
		for _, item := range c.Context.LinkTransformations {
			wire, err := proto.Marshal(item)
			if err != nil {
				return nil, err
			}
			out = appendBytes(out, wire)
		}
	}
	return out, nil
}

type cursor struct {
	data []byte
	err  error
}

func (c *cursor) unsigned() uint64 {
	if c.err != nil {
		return 0
	}
	v, n := binary.Uvarint(c.data)
	if n <= 0 {
		c.err = io.ErrUnexpectedEOF
		return 0
	}
	c.data = c.data[n:]
	return v
}
func (c *cursor) signed() int64 {
	if c.err != nil {
		return 0
	}
	v, n := binary.Varint(c.data)
	if n <= 0 {
		c.err = io.ErrUnexpectedEOF
		return 0
	}
	c.data = c.data[n:]
	return v
}
func (c *cursor) bytes() []byte {
	n := c.unsigned()
	if c.err != nil {
		return nil
	}
	if n > uint64(len(c.data)) {
		c.err = io.ErrUnexpectedEOF
		return nil
	}
	b := c.data[:int(n)]
	c.data = c.data[int(n):]
	return b
}
func (c *cursor) byte() byte {
	if c.err != nil {
		return 0
	}
	if len(c.data) == 0 {
		c.err = io.ErrUnexpectedEOF
		return 0
	}
	v := c.data[0]
	c.data = c.data[1:]
	return v
}
func (c *cursor) timestamp() time.Time {
	present := c.byte()
	if present == 0 {
		return time.Time{}
	}
	if present != 1 {
		c.err = fmt.Errorf("invalid stored timestamp marker")
		return time.Time{}
	}
	seconds, nanos := c.signed(), c.unsigned()
	if nanos >= 1e9 {
		c.err = fmt.Errorf("invalid stored nanoseconds")
	}
	return time.Unix(seconds, int64(nanos)).UTC()
}

func Unmarshal(wire []byte) (gopacket.CaptureInfo, error) {
	c := &cursor{data: wire}
	version := c.byte()
	if version != 1 && version != 2 {
		return gopacket.CaptureInfo{}, fmt.Errorf("unsupported capture metadata version")
	}
	flags := c.byte()
	if flags&^byte(15) != 0 {
		return gopacket.CaptureInfo{}, fmt.Errorf("invalid capture metadata flags")
	}
	saved := Capture{Timestamp: c.timestamp()}
	saved.CaptureLength, saved.Length, saved.Interface, saved.LogicalInterface = int(c.signed()), int(c.signed()), int(c.signed()), int(c.signed())
	saved.MissingTime, saved.FCS.Known, saved.FCS.Present = flags&1 != 0, flags&2 != 0, flags&4 != 0
	if flags&8 != 0 {
		saved.Context = &packetview.Context{Scope: string(c.bytes()), Status: string(c.bytes())}
		state := c.byte()
		if state&^byte(3) != 0 {
			return gopacket.CaptureInfo{}, fmt.Errorf("invalid packetview flags")
		}
		saved.Context.Reassembled, saved.Context.SyntheticNetwork = state&1 != 0, state&2 != 0
		saved.Context.CompletedAt = c.timestamp()
		n := c.unsigned()
		if n > uint64(len(c.data)) {
			return gopacket.CaptureInfo{}, io.ErrUnexpectedEOF
		}
		for range n {
			item := &types.Encapsulation{}
			if err := proto.Unmarshal(c.bytes(), item); err != nil {
				return gopacket.CaptureInfo{}, err
			}
			saved.Context.Tunnels = append(saved.Context.Tunnels, item)
		}
		n = c.unsigned()
		if n > uint64(len(c.data)) {
			return gopacket.CaptureInfo{}, io.ErrUnexpectedEOF
		}
		for range n {
			item := &types.CapturePacketRef{}
			if err := proto.Unmarshal(c.bytes(), item); err != nil {
				return gopacket.CaptureInfo{}, err
			}
			saved.Context.Packets = append(saved.Context.Packets, item)
		}
		if version == 2 {
			n = c.unsigned()
			if n > uint64(len(c.data)) {
				return gopacket.CaptureInfo{}, io.ErrUnexpectedEOF
			}
			for range n {
				item := &types.LinkTransformation{}
				if err := proto.Unmarshal(c.bytes(), item); err != nil {
					return gopacket.CaptureInfo{}, err
				}
				saved.Context.LinkTransformations = append(saved.Context.LinkTransformations, item)
			}
		}
	}
	if c.err != nil {
		return gopacket.CaptureInfo{}, c.err
	}
	if len(c.data) != 0 {
		return gopacket.CaptureInfo{}, fmt.Errorf("trailing capture metadata")
	}
	return saved.Restore(), nil
}
