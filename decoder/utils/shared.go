package utils

var (
	// AllDecoderNames contains the decoder names at runtime.
	AllDecoderNames = make(map[string]struct{})

	// ErrorMap contains error during reassembly at runtime.
	ErrorMap *AtomicCounterMap
)

// SetErrorMap sets the map for tracking errors
// it gets passed in from the collector during initialization
func SetErrorMap(e *AtomicCounterMap) {
	ErrorMap = e
}
