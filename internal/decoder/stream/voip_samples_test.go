package stream

import (
	"fmt"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/sipaudit"
	"github.com/dreadl0ck/netcap/types"
)

func prepareMediaSample(s sample, c *core.ConversationInfo) func() {
	if s.decoder != "RTP" {
		return func() {}
	}
	previous := sipaudit.Media
	sipaudit.Media = sipaudit.NewAssociations()
	if c.ClientIP == "" {
		c.ClientIP, c.ServerIP, c.ClientPort = "192.0.2.1", "192.0.2.2", 12345
	}
	if len(c.Data) == 0 {
		c.Data = core.DataFragments{hygieneFragment(s.client, 1e9, false), hygieneFragment(s.server, 3e9, true)}
	}
	for _, answer := range []bool{false, true} {
		ip, port := c.ClientIP, c.ClientPort
		if answer {
			ip, port = c.ServerIP, c.ServerPort
		}
		sipaudit.Media.Observe(&types.SIP{CallID: "matrix", From: "<sip:test@example.test>;tag=a", CSeqNumber: 1, CSeqMethod: "INVITE", MethodName: "INVITE", IsResponse: answer, ResponseCode: 200,
			ContentType: "application/sdp", Body: []byte(fmt.Sprintf("v=0\r\nc=IN IP4 %s\r\nm=audio %d RTP/AVP 0\r\n", ip, port))})
	}
	return func() { sipaudit.Media = previous }
}
