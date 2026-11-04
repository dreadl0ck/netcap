package tls

import (
	"sync/atomic"

	"github.com/dreadl0ck/tlsx"
	"github.com/gogo/protobuf/proto"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/internal/decoder"
	"github.com/dreadl0ck/netcap/internal/decoder/tlshello"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
)

var ClientHelloDecoder = &decoder.AbstractDecoder{Name: "TLSClientHello", Type: types.Type_NC_TLSClientHello, Description: "Reassembled TLS client hellos"}
var ServerHelloDecoder = &decoder.AbstractDecoder{Name: "TLSServerHello", Type: types.Type_NC_TLSServerHello, Description: "Reassembled TLS server hellos"}

func helloEnabled() bool { return ClientHelloDecoder.Writer != nil || ServerHelloDecoder.Writer != nil }

func (f *tlsRecordFramer) emitHello(message []byte) {
	if len(message) < 4 || len(message) > 65535 {
		return
	}
	// tlsx accepts a TLS record; the handshake has already been deframed.
	wire := append([]byte{22, 3, 3, byte(len(message) >> 8), byte(len(message))}, message...)
	c := f.reader.conversation
	var record proto.Message
	var d *decoder.AbstractDecoder
	switch message[0] {
	case handshakeTypeClientHello:
		if f.dir != reassembly.TCPDirClientToServer {
			return
		}
		if ClientHelloDecoder.Writer == nil {
			return
		}
		var hello tlsx.ClientHello
		if err := hello.Unmarshal(wire); err != nil {
			return
		}
		r := tlshello.Client(&hello, nil)
		r.Timestamp, r.SrcIP, r.DstIP, r.SrcPort, r.DstPort = f.handshakeTS, c.ClientIP, c.ServerIP, c.ClientPort, c.ServerPort
		r.CommunityID = c.CommunityID
		r.SrcMAC, r.DstMAC = c.ClientMAC, c.ServerMAC
		record, d = r, ClientHelloDecoder
	case handshakeTypeServerHello:
		if f.dir != reassembly.TCPDirServerToClient {
			return
		}
		if ServerHelloDecoder.Writer == nil {
			return
		}
		var hello tlsx.ServerHello
		if err := hello.Unmarshal(wire); err != nil {
			return
		}
		r := tlshello.Server(&hello, nil)
		r.Timestamp, r.SrcIP, r.DstIP, r.SrcPort, r.DstPort = f.handshakeTS, c.ServerIP, c.ClientIP, c.ServerPort, c.ClientPort
		r.CommunityID = c.CommunityID
		r.SrcMAC, r.DstMAC = c.ServerMAC, c.ClientMAC
		record, d = r, ServerHelloDecoder
	default:
		return
	}
	if err := d.Writer.Write(record); err != nil {
		tlsLog.Error("writing TLS hello", zap.Error(err))
	} else {
		atomic.AddInt64(&d.NumRecordsWritten, 1)
	}
}
