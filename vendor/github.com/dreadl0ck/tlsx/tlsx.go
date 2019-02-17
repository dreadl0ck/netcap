package tlsx

import "errors"

const (
	SNINameTypeDNS uint8 = 0
)

const (
	OCSPStatusRequest uint8 = 1
)

var (
	ErrHandshakeWrongType    = errors.New("handshake is of wrong type, or not a handshake message")
	ErrHandshakeBadLength    = errors.New("handshake has a malformed length")
	ErrHandshakeExtBadLength = errors.New("handshake extension has a malformed length")
)

type TLSMessage struct {
	Raw        []byte
	Type       uint8
	Version    Version
	MessageLen uint16
}
