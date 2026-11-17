package defaults

// TCP limits remain opt-in until finite-budget degradation preserves capture output.
const (
	MaxRetainedTCPBytes        int64 = 0
	MaxRetainedReassemblyBytes int64 = 0
	MaxRetainedTCPStateBytes   int64 = 0
	MaxAggregateStateBytes     int64 = 32 << 20
)
