package core

import "iter"

// SourceFragments preserves a walk's error alongside its lazy sequence.
func SourceFragments(source FragmentSource, result *error) iter.Seq[DataFragment] {
	return func(yield func(DataFragment) bool) { *result = source.Walk(yield) }
}

type MergedSource struct{ Client, Server FragmentSource }

func (s MergedSource) Count() int64 { return s.Client.Count() + s.Server.Count() }
func (s MergedSource) Walk(yield func(DataFragment) bool) error {
	var clientErr, serverErr error
	client, stopClient := iter.Pull(SourceFragments(s.Client, &clientErr))
	defer stopClient()
	server, stopServer := iter.Pull(SourceFragments(s.Server, &serverErr))
	defer stopServer()
	a, haveA := client()
	b, haveB := server()
	for haveA || haveB {
		if clientErr != nil {
			return clientErr
		}
		if serverErr != nil {
			return serverErr
		}
		if haveB && (!haveA || FragmentBefore(b, a)) {
			if !yield(b) {
				return nil
			}
			b, haveB = server()
		} else {
			if !yield(a) {
				return nil
			}
			a, haveA = client()
		}
	}
	if clientErr != nil {
		return clientErr
	}
	return serverErr
}

// FragmentSource is restartable. A walk retains only the current fragment unless
// the consumer explicitly keeps it; returning false stops that pass.
type FragmentSource interface {
	Walk(func(DataFragment) bool) error
	Count() int64
}

type FragmentSourceDecoder interface{ SupportsFragmentSource() bool }

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
