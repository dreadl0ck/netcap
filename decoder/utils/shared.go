package utils

var (
	AllDecoderNames = make(map[string]struct{})
	ErrorMap        *AtomicCounterMap
)

// SetErrorMap sets the map for tracking errors
// it gets passed in from the collector during initialization
func SetErrorMap(e *AtomicCounterMap) {
	ErrorMap = e
}
