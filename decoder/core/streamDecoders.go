package core

type TransportProtocol int

const (
	TCP TransportProtocol = iota
	UDP
	All
)

// StreamDecoderAPI describes an interface that all stream decoders need to implement
// this allows to supply a custom structure and maintain state for advanced protocol analysis.
type StreamDecoderAPI interface {
	DecoderAPI

	// CanDecodeStream determines if this decoder can understand the protocol used
	CanDecodeStream(client []byte, server []byte) bool

	// GetReaderFactory returns a factory for processing streams of the current encoder
	GetReaderFactory() StreamDecoderFactory

	Transport() TransportProtocol
}

// StreamDecoderFactory produces stream decoder instances.
type StreamDecoderFactory interface {

	// New StreamDecoderInterface
	New(conversation *ConversationInfo) StreamDecoderInterface
}

// StreamDecoderInterface is the interface for processing a bi-directional network connection.
type StreamDecoderInterface interface {

	// Decode parses the stream according to the identified protocol.
	Decode()
}
