package core

import "time"

// ConversationInfo is wrapper structure for traffic sent over a Transport protocol
// to allow Transport agnostic decoding of data streams.
type ConversationInfo struct {
	Data              DataFragments
	Ident             string
	FirstClientPacket time.Time
	FirstServerPacket time.Time

	ClientIP   string
	ServerIP   string
	ClientPort int32
	ServerPort int32
}
