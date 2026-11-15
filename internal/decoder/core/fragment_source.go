package core

import "iter"

// FragmentSource is restartable. A walk retains only the current fragment unless
// the consumer explicitly keeps it; returning false stops that pass.
type FragmentSource interface {
	Walk(func(DataFragment) bool) error
	Count() int64
}

type SliceSource DataFragments

func (s SliceSource) Count() int64 { return int64(len(s)) }
func (s SliceSource) Walk(yield func(DataFragment) bool) error {
	for _, f := range s {
		if !yield(f) {
			break
		}
	}
	return nil
}

func (c *ConversationInfo) Fragments() iter.Seq[DataFragment] {
	return func(yield func(DataFragment) bool) {
		if c.Source != nil {
			if err := c.Source.Walk(yield); err != nil {
				c.FragmentError = err
			}
			return
		}
		for _, fragment := range c.Data {
			if !yield(fragment) {
				return
			}
		}
	}
}

func (c *ConversationInfo) FragmentCount() int64 {
	if c.Source != nil {
		return c.Source.Count()
	}
	return int64(len(c.Data))
}
