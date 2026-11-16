package network

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/dreadl0ck/netcap/internal/aggregate"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/internal/packetmeta"
	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/gopacket/gopacket"
)

func networkOrdinal(ci gopacket.CaptureInfo) uint64 {
	if context := packetview.FromCapture(ci); context != nil && len(context.Packets) > 0 && context.Packets[0] != nil {
		return context.Packets[0].Ordinal
	}
	return 0
}

func networkFlowKey(key uint64) string    { return fmt.Sprintf("network/flows/%016x", key) }
func networkDataPrefix(key uint64) string { return fmt.Sprintf("network/data/%016x/", key) }

func appendNetworkBytes(out, value []byte) []byte {
	out = binary.AppendUvarint(out, uint64(len(value)))
	return append(out, value...)
}

func encodeNetworkData(packet gopacket.Packet, payload []byte, protocol string) ([]byte, error) {
	metadata, err := packetmeta.Marshal(packet.Metadata().CaptureInfo)
	if err != nil {
		return nil, err
	}
	flag := byte(0)
	if payload == nil {
		flag = 1
	}
	flow := packet.NetworkLayer().NetworkFlow()
	out := binary.AppendVarint([]byte{1, flag}, int64(flow.EndpointType()))
	out = appendNetworkBytes(out, metadata)
	out = appendNetworkBytes(out, flow.Src().Raw())
	out = appendNetworkBytes(out, flow.Dst().Raw())
	out = appendNetworkBytes(out, []byte(protocol))
	return append(out, payload...), nil
}

func decodeNetworkData(wire []byte) (*NetworkData, error) {
	if len(wire) < 3 || wire[0] != 1 || wire[1] > 1 {
		return nil, fmt.Errorf("invalid stored network datagram")
	}
	flag := wire[1]
	kind, n := binary.Varint(wire[2:])
	if n <= 0 {
		return nil, io.ErrUnexpectedEOF
	}
	wire = wire[2+n:]
	var fields [4][]byte
	for i := range fields {
		size, n := binary.Uvarint(wire)
		if n <= 0 || size > uint64(len(wire)-max(n, 0)) {
			return nil, io.ErrUnexpectedEOF
		}
		fields[i], wire = wire[n:n+int(size)], wire[n+int(size):]
	}
	if len(fields[1]) > 16 || len(fields[2]) > 16 {
		return nil, fmt.Errorf("stored network endpoint exceeds 16 bytes")
	}
	ci, err := packetmeta.Unmarshal(fields[0])
	if err != nil {
		return nil, err
	}
	if flag == 1 {
		if len(wire) != 0 {
			return nil, fmt.Errorf("nil network payload carries bytes")
		}
		wire = nil
	} else if wire == nil {
		wire = []byte{}
	}
	return &NetworkData{RawData: wire, CaptureInformation: ci, Net: gopacket.NewFlow(gopacket.EndpointType(kind), fields[1], fields[2]), Protocol: string(fields[3])}, nil
}

func storeNetworkPacket(packet gopacket.Packet, payload []byte, protocol string) {
	key := packet.NetworkLayer().NetworkFlow().FastHash() ^ packetview.ScopeHash(packet)
	_ = decoderconfig.Instance.AggregateStore.Do(func(tx *aggregate.Tx) error {
		flow, found, err := tx.Get(networkFlowKey(key))
		if err != nil {
			return err
		}
		count := uint64(0)
		if found {
			if len(flow) < 8 {
				return fmt.Errorf("invalid stored network flow")
			}
			count = binary.LittleEndian.Uint64(flow)
		} else {
			flow = append(make([]byte, 8), protocol...)
		}
		if count == ^uint64(0) {
			return fmt.Errorf("network datagram counter exhausted")
		}
		count++
		wire, err := encodeNetworkData(packet, payload, protocol)
		if err != nil {
			return err
		}
		ci := packet.Metadata().CaptureInfo
		dataKey := fmt.Sprintf("%s%016x/%08x/%016x/%016x", networkDataPrefix(key), uint64(ci.Timestamp.Unix())^(uint64(1)<<63), uint32(ci.Timestamp.Nanosecond()), networkOrdinal(ci), count)
		if err := tx.Put(dataKey, wire); err != nil {
			return err
		}
		binary.LittleEndian.PutUint64(flow, count)
		return tx.Put(networkFlowKey(key), flow)
	})
}

type networkFragmentSource struct {
	state  *aggregate.Store
	prefix string
	client gopacket.Flow
}

func (s *networkFragmentSource) Walk(yield func(streamutils.NetworkDataFragment) bool) error {
	last := ""
	for {
		var key string
		var wire []byte
		var found bool
		err := s.state.Do(func(tx *aggregate.Tx) error {
			var err error
			key, wire, found, err = tx.Next(s.prefix, last)
			return err
		})
		if err != nil || !found {
			return err
		}
		data, err := decodeNetworkData(wire)
		if err != nil {
			return err
		}
		data.Dir = reassembly.TCPDirClientToServer
		if s.client != (gopacket.Flow{}) && data.Network() != s.client {
			data.Dir = reassembly.TCPDirServerToClient
		}
		if !yield(data) {
			return nil
		}
		last = key
	}
}

func flushStoredNetwork() {
	state := decoderconfig.Instance.AggregateStore
	last := ""
	for {
		var key string
		var id uint64
		var protocol string
		var found bool
		err := state.Do(func(tx *aggregate.Tx) error {
			var wire []byte
			var err error
			key, wire, found, err = tx.Next("network/flows/", last)
			if err != nil || !found {
				return err
			}
			if len(wire) < 8 || binary.LittleEndian.Uint64(wire) == 0 {
				return fmt.Errorf("invalid stored network flow")
			}
			protocol = string(wire[8:])
			_, err = fmt.Sscanf(key, "network/flows/%x", &id)
			return err
		})
		if err != nil || !found {
			return
		}
		source := &networkFragmentSource{state: state, prefix: networkDataPrefix(id)}
		var first streamutils.NetworkDataFragment
		err = source.Walk(func(data streamutils.NetworkDataFragment) bool { first = data; return false })
		if err == nil && first == nil {
			err = fmt.Errorf("stored network flow has no datagrams")
		}
		if err == nil {
			source.client = first.Network()
			start := time.Now()
			err = streamutils.SaveNetworkSource(protocol, source, createNetworkFlowIdent(first.Network()), first.CaptureInfo().Timestamp)
			networkStreamProcessingTime.WithLabelValues(protocol).Set(float64(time.Since(start).Nanoseconds()))
		}
		if err != nil {
			_ = state.Do(func(*aggregate.Tx) error { return err })
			return
		}
		last = key
	}
}
