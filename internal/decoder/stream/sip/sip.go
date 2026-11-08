package sip

import (
	"bytes"
	"sync/atomic"

	"github.com/dreadl0ck/netcap/internal/decoder"
	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/internal/sipaudit"
	"github.com/dreadl0ck/netcap/types"
)

var Decoder = &decoder.StreamDecoder{
	Type: types.Type_NC_SIP, Name: "SIP", Description: "Content-Length framed SIP over TCP",
	Typ: core.TCP, Specificity: core.SpecificityValidated, Factory: &reader{},
	CanDecode: func(client, server []byte) bool { return probe(client) || probe(server) },
}

func probe(data []byte) bool {
	_, _, err := sipaudit.Parse(bytes.TrimLeft(data, "\r\n"), true)
	return err == nil
}

type reader struct{ conversation *core.ConversationInfo }

func (*reader) New(c *core.ConversationInfo) core.StreamDecoderInterface { return &reader{c} }
func (r *reader) Decode() {
	r.decode(func(msg *types.SIP) {
		if Decoder.Writer != nil && Decoder.Writer.Write(msg) == nil {
			atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
		}
	})
}

func (r *reader) decode(emit func(*types.SIP)) {
	for _, run := range streamutils.TransportRuns(r.conversation) {
		r.decodeRun(run.Conversation, run.Observation, emit)
	}
}

func (r *reader) decodeRun(c *core.ConversationInfo, observation string, emit func(*types.SIP)) {
	directions := []core.DataFragments{c.ClientData, c.ServerData}
	if len(c.ClientData)+len(c.ServerData) == 0 {
		for _, f := range c.Data {
			side := 0
			if core.FromServer(f) {
				side = 1
			}
			directions[side] = append(directions[side], f)
		}
	}
	for _, fragments := range directions {
		var buf []byte
		var at int64
		broken := false
		observed := false
		for _, f := range fragments {
			if loss, ok := f.(*core.StreamData); ok && (loss.SkippedBytes != 0 || loss.DiscardedBytes > 0) {
				// Only an unknown leading prefix may begin at an observed SIP boundary.
				if loss.SkippedBytes > 0 || loss.DiscardedBytes > 0 || observed {
					broken = true
				}
			}
			if broken {
				break
			}
			data := f.Raw()
			observed = observed || len(data) > 0
			for len(data) > 0 {
				if len(buf) == 0 {
					data = bytes.TrimLeft(data, "\r\n")
					at = core.FragmentTime(f)
					if len(data) == 0 {
						break
					}
				}
				n := min(len(data), sipaudit.MaxHeader+sipaudit.MaxBody+4-len(buf))
				if n == 0 {
					broken = true
					break
				}
				buf = append(buf, data[:n]...)
				data = data[n:]
				for len(buf) > 0 {
					wire, used, err := sipaudit.Parse(buf, true)
					if err == sipaudit.ErrIncomplete {
						break
					}
					if err != nil {
						broken = true
						break
					}
					msg := sipaudit.Record(wire, at)
					msg.SrcIP, msg.DstIP, msg.SrcPort, msg.DstPort = c.Endpoints(f)
					msg.CommunityID, msg.Transport = c.CommunityID, "TCP"
					msg.NetworkScope = c.NetworkScope
					msg.TCPObservation = observation
					sipaudit.Analyze(msg)
					sipaudit.Media.Observe(msg)
					if config.Instance == nil || !config.Instance.IncludePayloads {
						msg.Body = nil
					} else {
						msg.Body = bytes.Clone(msg.Body)
					}
					emit(msg)
					buf = bytes.TrimLeft(buf[used:], "\r\n")
					at = core.FragmentTime(f)
				}
				if broken {
					break
				}
			}
		}
	}
}
