package dns

import (
	"encoding/binary"
	"sync/atomic"

	"github.com/dreadl0ck/netcap/internal/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/dnsaudit"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var Decoder = &decoder.StreamDecoder{
	Type: types.Type_NC_DNS, Name: "DNS", Description: "Length-framed DNS over TCP",
	Specificity: core.SpecificityWeak, Typ: core.TCP, Factory: &reader{},
	CanDecode: func(client, server []byte) bool { return probe(client) || probe(server) },
}

func probe(data []byte) bool {
	if len(data) < 14 {
		return false
	}
	n := int(binary.BigEndian.Uint16(data))
	if n < 12 || n+2 > len(data) {
		return false
	}
	var message layers.DNS
	return message.DecodeFromBytes(data[2:n+2], gopacket.NilDecodeFeedback) == nil &&
		message.OpCode <= 5 && (len(message.Questions) > 0 || len(message.Answers) > 0)
}

type reader struct{ conversation *core.ConversationInfo }

func (*reader) New(c *core.ConversationInfo) core.StreamDecoderInterface {
	return &reader{conversation: c}
}

func (r *reader) Decode() {
	r.decode(func(message *types.DNS) {
		if Decoder.Writer != nil && Decoder.Writer.Write(message) == nil {
			atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
		}
	})
}

func (r *reader) decode(emit func(*types.DNS)) {
	calculateEntropy := decoderconfig.Instance != nil && decoderconfig.Instance.CalculateEntropy
	fragments := r.conversation.Data
	if len(fragments) == 0 {
		fragments = append(append(core.DataFragments{}, r.conversation.ClientData...), r.conversation.ServerData...)
	}
	type side struct {
		data []byte
		at   int64
	}
	var sides [2]side
	tracker := dnsaudit.NewDNSTransactionTracker()
	for _, fragment := range fragments {
		direction := 0
		if core.FromServer(fragment) {
			direction = 1
		}
		buffer := &sides[direction]
		if loss, ok := fragment.(*core.StreamData); ok && loss.SkippedBytes != 0 {
			buffer.data = nil
			tracker = dnsaudit.NewDNSTransactionTracker()
			continue
		}
		data := fragment.Raw()
		for len(data) > 0 {
			if len(buffer.data) == 0 {
				buffer.at = core.FragmentTime(fragment)
			}
			if len(buffer.data) < 2 {
				n := min(2-len(buffer.data), len(data))
				buffer.data = append(buffer.data, data[:n]...)
				data = data[n:]
				if len(buffer.data) < 2 {
					break
				}
			}
			size := int(binary.BigEndian.Uint16(buffer.data))
			if size < 12 {
				buffer.data = nil
				break
			}
			n := min(size+2-len(buffer.data), len(data))
			buffer.data = append(buffer.data, data[:n]...)
			data = data[n:]
			if len(buffer.data) < size+2 {
				break
			}
			var wire layers.DNS
			body := append([]byte(nil), buffer.data[2:]...)
			if wire.DecodeFromBytes(body, gopacket.NilDecodeFeedback) == nil {
				message := dnsaudit.Record(&wire, buffer.at, calculateEntropy)
				message.SrcIP, message.DstIP, message.SrcPort, message.DstPort = r.conversation.Endpoints(fragment)
				message.CommunityID = r.conversation.CommunityID
				tracker.Observe(message)
				emit(message)
			}
			buffer.data = buffer.data[:0]
		}
	}
}
