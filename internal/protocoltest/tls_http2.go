package protocoltest

import (
	"bytes"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/dreadl0ck/netcap/internal/utils"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type TLSHTTP2Message struct {
	Direction string      `json:"direction"`
	StreamID  uint32      `json:"streamId"`
	Headers   [][2]string `json:"headers"`
	Body      []byte      `json:"body,omitempty"`
	BodyText  string      `json:"bodyText,omitempty"`
	Truncated bool        `json:"truncated,omitempty"`
}

func decodeTLSHTTP2(node0, node1 []byte) ([]TLSHTTP2Message, []string) {
	if !bytes.HasPrefix(node0, []byte(http2.ClientPreface)) && !bytes.HasPrefix(node1, []byte(http2.ClientPreface)) {
		return nil, nil
	}
	var messages []TLSHTTP2Message
	var issues []string
	bodyBytes := 0
	for side, data := range [][]byte{node0, node1} {
		if bytes.HasPrefix(data, []byte(http2.ClientPreface)) {
			data = data[len(http2.ClientPreface):]
		}
		framer := http2.NewFramer(io.Discard, bytes.NewReader(data))
		framer.SetMaxReadFrameSize(1 << 20)
		framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
		framer.MaxHeaderListSize = 64 << 10
		indices := make(map[uint32]int)
		for frames := 0; ; frames++ {
			if frames >= 100000 {
				issues = append(issues, fmt.Sprintf("node%d: HTTP/2 frame limit", side))
				break
			}
			frame, err := framer.ReadFrame()
			if err == io.EOF {
				break
			}
			if err != nil {
				issues = append(issues, fmt.Sprintf("node%d: incomplete or invalid HTTP/2 frames: %v", side, err))
				break
			}
			id := frame.Header().StreamID
			if id == 0 {
				continue
			}
			index, known := indices[id]
			switch frame.(type) {
			case *http2.MetaHeadersFrame, *http2.DataFrame:
			default:
				continue
			}
			if !known {
				if len(indices) >= 128 {
					issues = append(issues, fmt.Sprintf("node%d: HTTP/2 stream limit", side))
					break
				}
				index = len(messages)
				indices[id] = index
				messages = append(messages, TLSHTTP2Message{Direction: fmt.Sprintf("node%d", side), StreamID: id})
			}
			message := &messages[index]
			switch frame := frame.(type) {
			case *http2.MetaHeadersFrame:
				message.Truncated = message.Truncated || frame.Truncated
				for _, field := range frame.Fields {
					if len(message.Headers) >= 256 {
						message.Truncated = true
						break
					}
					message.Headers = append(message.Headers, [2]string{utils.PrintableBytes([]byte(field.Name)), utils.PrintableBytes([]byte(field.Value))})
				}
			case *http2.DataFrame:
				available := min(len(frame.Data()), (1<<20)-len(message.Body), (8<<20)-bodyBytes)
				message.Body = append(message.Body, frame.Data()[:available]...)
				bodyBytes += available
				message.Truncated = message.Truncated || available < len(frame.Data())
			}
		}
	}
	for i := range messages {
		if utf8.Valid(messages[i].Body) {
			messages[i].BodyText = string(messages[i].Body)
		}
	}
	return messages, issues
}
