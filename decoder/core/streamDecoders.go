package core

// StreamDecoderAPI describes an interface that all stream decoders need to implement
// this allows to supply a custom structure and maintain state for advanced protocol analysis.
type StreamDecoderAPI interface {
	DecoderAPI

	// CanDecode determines if this decoder can understand the protocol used
	CanDecode(client []byte, server []byte) bool

	// GetReaderFactory returns a factory for processing streams of the current encoder
	GetReaderFactory() StreamDecoderFactory
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
