package udp

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/dreadl0ck/netcap/internal/aggregate"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream"
	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/internal/packetmeta"
	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/internal/utils"
	"github.com/gopacket/gopacket"
)

type storedUDPFlow struct {
	count   uint64
	scope   string
	refused bool
}

func udpFlowKey(key uint64) string    { return fmt.Sprintf("udp/flows/%016x", key) }
func udpDataPrefix(key uint64) string { return fmt.Sprintf("udp/data/%016x/", key) }
func encodeUDPFlow(f storedUDPFlow) []byte {
	out := binary.LittleEndian.AppendUint64(nil, f.count)
	flag := byte(0)
	if f.refused {
		flag = 1
	}
	out = append(out, flag)
	return append(out, []byte(f.scope)...)
}
func decodeUDPFlow(wire []byte) (storedUDPFlow, error) {
	if len(wire) < 9 || wire[8] > 1 {
		return storedUDPFlow{}, fmt.Errorf("invalid stored UDP flow")
	}
	return storedUDPFlow{count: binary.LittleEndian.Uint64(wire), scope: string(wire[9:]), refused: wire[8] == 1}, nil
}

func udpAppendBytes(out, data []byte) []byte {
	out = binary.AppendUvarint(out, uint64(len(data)))
	return append(out, data...)
}
func udpAppendFlow(out []byte, flow gopacket.Flow) []byte {
	out = binary.AppendVarint(out, int64(flow.EndpointType()))
	out = udpAppendBytes(out, flow.Src().Raw())
	return udpAppendBytes(out, flow.Dst().Raw())
}

func encodeUDPData(packet gopacket.Packet, payload []byte) ([]byte, error) {
	metadata, err := packetmeta.Marshal(packet.Metadata().CaptureInfo)
	if err != nil {
		return nil, err
	}
	flag := byte(0)
	if payload == nil {
		flag = 1
	}
	out := udpAppendBytes([]byte{1, flag}, metadata)
	out = udpAppendFlow(out, packet.NetworkLayer().NetworkFlow())
	out = udpAppendFlow(out, packet.TransportLayer().TransportFlow())
	return append(out, payload...), nil
}

type udpCursor struct {
	data []byte
	err  error
}

func (c *udpCursor) bytes() []byte {
	if c.err != nil {
		return nil
	}
	n, size := binary.Uvarint(c.data)
	if size <= 0 || n > uint64(len(c.data)-max(size, 0)) {
		c.err = io.ErrUnexpectedEOF
		return nil
	}
	c.data = c.data[size:]
	out := c.data[:int(n)]
	c.data = c.data[int(n):]
	return out
}
func (c *udpCursor) flow() gopacket.Flow {
	if c.err != nil {
		return gopacket.Flow{}
	}
	typ, n := binary.Varint(c.data)
	if n <= 0 {
		c.err = io.ErrUnexpectedEOF
		return gopacket.Flow{}
	}
	c.data = c.data[n:]
	src, dst := c.bytes(), c.bytes()
	if len(src) > 16 || len(dst) > 16 {
		c.err = fmt.Errorf("stored UDP endpoint exceeds 16 bytes")
		return gopacket.Flow{}
	}
	if c.err != nil {
		return gopacket.Flow{}
	}
	return gopacket.NewFlow(gopacket.EndpointType(typ), src, dst)
}

func decodeUDPData(wire []byte) (*core.StreamData, error) {
	if len(wire) < 2 || wire[0] != 1 || wire[1] > 1 {
		return nil, fmt.Errorf("invalid stored UDP datagram")
	}
	c := &udpCursor{data: wire[2:]}
	metadata := c.bytes()
	if c.err != nil {
		return nil, c.err
	}
	ci, err := packetmeta.Unmarshal(metadata)
	if err != nil {
		return nil, err
	}
	network, transport := c.flow(), c.flow()
	if c.err != nil {
		return nil, c.err
	}
	payload := c.data
	if wire[1] == 1 {
		if len(payload) != 0 {
			return nil, fmt.Errorf("nil stored payload contains bytes")
		}
		payload = nil
	} else if payload == nil {
		payload = []byte{}
	}
	return &core.StreamData{RawData: payload, CaptureInformation: ci, Net: network, Trans: transport}, nil
}

func (u *udpStreamPool) storePacket(packet gopacket.Packet, payload []byte) {
	key := udpConversationKey(packet)
	_ = decoderconfig.Instance.AggregateStore.Do(func(tx *aggregate.Tx) error {
		wire, found, err := tx.Get(udpFlowKey(key))
		if err != nil {
			return err
		}
		flow := storedUDPFlow{scope: packetview.Scope(packet)}
		if found {
			flow, err = decodeUDPFlow(wire)
			if err != nil {
				return err
			}
		}
		if flow.count == ^uint64(0) {
			return fmt.Errorf("UDP datagram counter exhausted")
		}
		flow.count++
		wire, err = encodeUDPData(packet, payload)
		if err != nil {
			return err
		}
		ci := packet.Metadata().CaptureInfo
		var ordinal uint64
		if context := packetview.FromCapture(ci); context != nil && len(context.Packets) > 0 {
			ordinal = context.Packets[0].Ordinal
		}
		dataKey := fmt.Sprintf("%s%016x/%08x/%016x/%016x", udpDataPrefix(key), uint64(ci.Timestamp.Unix())^(uint64(1)<<63), uint32(ci.Timestamp.Nanosecond()), ordinal, flow.count)
		if err = tx.Put(dataKey, wire); err != nil {
			return err
		}
		return tx.Put(udpFlowKey(key), encodeUDPFlow(flow))
	})
}

type udpFragmentSource struct {
	state                          *aggregate.Store
	prefix                         string
	count                          int64
	roles                          bool
	clientNetwork, clientTransport gopacket.Flow
}

func (s *udpFragmentSource) Count() int64 { return s.count }
func (s *udpFragmentSource) Walk(yield func(core.DataFragment) bool) error {
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
		fragment, err := decodeUDPData(wire)
		if err != nil {
			_ = s.state.Do(func(*aggregate.Tx) error { return err })
			return err
		}
		if s.roles && !(fragment.Network() == s.clientNetwork && fragment.Transport() == s.clientTransport) {
			fragment.Dir = reassembly.TCPDirServerToClient
		}
		if !yield(fragment) {
			return nil
		}
		last = key
	}
}

func processStoredUDP(key uint64, flow storedUDPFlow) error {
	state := decoderconfig.Instance.AggregateStore
	if flow.count > uint64(^uint64(0)>>1) {
		return fmt.Errorf("UDP datagram count exceeds signed range")
	}
	source := &udpFragmentSource{state: state, prefix: udpDataPrefix(key), count: int64(flow.count)}
	var first core.DataFragment
	if err := source.Walk(func(f core.DataFragment) bool { first = f; return false }); err != nil {
		return err
	}
	if first == nil {
		return fmt.Errorf("stored UDP flow has no datagrams")
	}
	clientNetwork, clientTransport := clientFlows(core.DataFragments{first})
	source.roles, source.clientNetwork, source.clientTransport = true, clientNetwork, clientTransport
	var client, server, banner []byte
	var firstClient, firstServer time.Time
	var clientBytes, serverBytes int
	bannerFound := false
	if err := source.Walk(func(f core.DataFragment) bool {
		if core.FromServer(f) {
			serverBytes += len(f.Raw())
			if server == nil {
				server = f.Raw()
				firstServer = f.CaptureInfo().Timestamp
			}
			if !bannerFound {
				banner = append([]byte(nil), f.Raw()[:min(len(f.Raw()), decoderconfig.Instance.BannerSize)]...)
				bannerFound = true
			}
		} else {
			clientBytes += len(f.Raw())
			if client == nil {
				client = f.Raw()
				firstClient = f.CaptureInfo().Timestamp
			}
		}
		return true
	}); err != nil {
		return err
	}
	ident := utils.CreateFlowIdentFromLayerFlows(clientNetwork, clientTransport)
	cid := streamutils.CalcCommunityIDUDP(clientNetwork.Src().String(), clientNetwork.Dst().String(), uint16(utils.DecodePort(clientTransport.Src().Raw())), uint16(utils.DecodePort(clientTransport.Dst().Raw())))
	conversation := &core.ConversationInfo{Transport: core.UDP, Source: source, NetworkScope: flow.scope, Ident: ident, FirstClientPacket: firstClient, FirstServerPacket: firstServer, ClientIP: clientNetwork.Src().String(), ServerIP: clientNetwork.Dst().String(), ClientPort: utils.DecodePort(clientTransport.Src().Raw()), ServerPort: utils.DecodePort(clientTransport.Dst().Raw()), CommunityID: cid}
	if selection, ok := stream.SelectDecoder(&stream.SelectionInput{Transport: core.UDP, ServerPort: conversation.ServerPort, PortClient: client, PortServer: server, ScanClient: client, ScanServer: server, Conversation: conversation}); ok {
		selection.Decoder.Decode()
	}
	if conversation.FragmentError != nil {
		return conversation.FragmentError
	}
	if err := streamutils.SaveDatagramConversation(source, ident, first.CaptureInfo().Timestamp, clientTransport, cid); err != nil {
		return err
	}
	if !flow.refused || serverBytes > 0 {
		saveUDPServiceBanner(banner, ident, clientNetwork.Dst().String()+":"+clientTransport.Dst().String(), first.CaptureInfo().Timestamp, serverBytes, clientBytes, clientNetwork, clientTransport)
	}
	return nil
}

func flushStoredUDP() {
	state := decoderconfig.Instance.AggregateStore
	last := ""
	for {
		var key string
		var flow storedUDPFlow
		var found bool
		err := state.Do(func(tx *aggregate.Tx) error {
			var wire []byte
			var err error
			key, wire, found, err = tx.Next("udp/flows/", last)
			if err != nil || !found {
				return err
			}
			flow, err = decodeUDPFlow(wire)
			return err
		})
		if err != nil || !found {
			break
		}
		var id uint64
		if _, err = fmt.Sscanf(key, "udp/flows/%x", &id); err == nil {
			err = processStoredUDP(id, flow)
		}
		if err != nil {
			_ = state.Do(func(*aggregate.Tx) error { return err })
			break
		}
		last = key
	}
	writeAssociationCoverage()
}
