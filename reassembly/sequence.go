package reassembly

const (
	invalidSequence = -1
	uint32Max       = 0xFFFFFFFF
)

// Sequence is a TCP sequence number.  It provides a few convenience functions
// for handling TCP wrap-around.  The sequence should always be in the range
// [0,0xFFFFFFFF]... its other bits are simply used in wrap-around calculations
// and should never be set.
type Sequence int64

// difference defines an ordering for comparing TCP sequences that's safe for
// roll-overs.  It returns:
//    > 0 : if t comes after s
//    < 0 : if t comes before s
//      0 : if t == s
// The number returned is the sequence difference, so 4.Difference(8) will
// return 4.
//
// It handles rollovers by considering any sequence in the first quarter of the
// uint32 space to be after any sequence in the last quarter of that space, thus
// wrapping the uint32 space.
func (s Sequence) difference(t Sequence) int {
	if s > uint32Max-uint32Max/4 && t < uint32Max/4 {
		t += uint32Max
	} else if t > uint32Max-uint32Max/4 && s < uint32Max/4 {
		s += uint32Max
	}
	return int(t - s)
}

// add adds an integer to a sequence and returns the resulting sequence.
func (s Sequence) add(t int) Sequence {
	return (s + Sequence(t)) & uint32Max
}
