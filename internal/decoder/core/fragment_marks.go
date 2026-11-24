package core

// FragmentMark locates a fragment that may carry loss, discard or TCP observation
// metadata. PayloadEnd is one past the last non-empty fragment before it, 0 if none.
type FragmentMark struct{ Index, PayloadEnd int64 }

// MarkedSource indexes every position whose fragment can carry such metadata, so
// consumers that only need boundaries can skip payload walks. ok=false means unknown.
type MarkedSource interface {
	FragmentMarks() (marks []FragmentMark, ok bool)
}

// MaxFragmentMarks bounds the index; a source with more marks reports none.
const MaxFragmentMarks = 4096

func SourceMarks(source FragmentSource) ([]FragmentMark, bool) {
	if marked, ok := source.(MarkedSource); ok {
		return marked.FragmentMarks()
	}
	return nil, false
}

func (s fragmentRange) FragmentMarks() ([]FragmentMark, bool) {
	marks, ok := SourceMarks(s.source)
	if !ok || CheckFragmentRange(s.source.Count(), s.start, s.count) != nil {
		return nil, false
	}
	var out []FragmentMark
	for _, m := range marks {
		if m.Index >= s.start && m.Index < s.start+s.count {
			out = append(out, FragmentMark{Index: m.Index - s.start, PayloadEnd: max(0, m.PayloadEnd-s.start)})
		}
	}
	return out, true
}

// MarkedFragment reads the fragment at a mark without walking the payload before it.
func MarkedFragment(source RangedFragmentSource, index int64) (*StreamData, error) {
	var data *StreamData
	err := source.WalkRange(index, 1, func(f DataFragment) bool {
		data, _ = f.(*StreamData)
		return false
	})
	return data, err
}

// SizedSource reports the payload bytes a full walk would yield, when known.
type SizedSource interface {
	PayloadBytes() (int64, bool)
}

func SourcePayloadBytes(source FragmentSource) (int64, bool) {
	if sized, ok := source.(SizedSource); ok {
		return sized.PayloadBytes()
	}
	return 0, false
}
