package tls

import (
	"github.com/dreadl0ck/netcap/internal/decoder/core"
)

type trimmedDirection struct {
	source core.RangedFragmentSource
	skip   int
}

func (s trimmedDirection) Count() int64 { return s.source.Count() }
func (s trimmedDirection) Walk(yield func(core.DataFragment) bool) error {
	return s.WalkRange(0, s.Count(), yield)
}
func (s trimmedDirection) WalkRange(start, count int64, yield func(core.DataFragment) bool) error {
	first := start == 0
	return s.source.WalkRange(start, count, func(fragment core.DataFragment) bool {
		if !first || s.skip == 0 {
			return yield(fragment)
		}
		first = false
		data := &core.StreamData{RawData: fragment.Raw()[s.skip:], Dir: fragment.Direction(), AssemblerContext: fragment.Context(), CaptureInformation: fragment.CaptureInfo(), Net: fragment.Network(), Trans: fragment.Transport()}
		if original, ok := fragment.(*core.StreamData); ok {
			copy := *original
			copy.RawData = copy.RawData[s.skip:]
			copy.SkippedBytes = 0
			data = &copy
		}
		return yield(data)
	})
}

func trimDirection(source core.RangedFragmentSource, bound int) (core.RangedFragmentSource, error) {
	var dropped int64
	position, skip := 0, 0
	err := source.Walk(func(fragment core.DataFragment) bool {
		start := position
		position += len(fragment.Raw())
		if position < bound || position == bound && len(fragment.Raw()) > 0 {
			dropped++
			return true
		}
		skip = max(0, bound-start)
		return false
	})
	if err != nil {
		return nil, err
	}
	return trimmedDirection{core.FragmentRange(source, dropped, source.Count()-dropped), skip}, nil
}

func observeSourceUpgradeRun(c *core.ConversationInfo, primary, note string) error {
	prefix := func(source core.FragmentSource) byte {
		var data []byte
		err := source.Walk(func(fragment core.DataFragment) bool {
			if d, ok := fragment.(*core.StreamData); ok && (d.DiscardedBytes > 0 || d.SkippedBytes != 0 && (d.SkippedBytes > 0 || len(data) > 0)) {
				return false
			}
			data = append(data, fragment.Raw()[:min(14-len(data), len(fragment.Raw()))]...)
			return len(data) < 14
		})
		if err != nil {
			c.FragmentError = err
		}
		return helloPrefixType(core.DataFragments{&core.StreamData{RawData: data}})
	}
	clientHello, serverHello := prefix(c.ClientSource), prefix(c.ServerSource)
	if c.FragmentError != nil {
		return c.FragmentError
	}
	if clientHello == 1 || serverHello == 1 {
		reader := &tlsReader{conversation: c, transportObservation: note}
		reader.frameTransportRun()
		return c.FragmentError
	}
	bounds, ok := negotiatedUpgradeSource(c, primary)
	if c.FragmentError != nil {
		return c.FragmentError
	}
	if !ok {
		return nil
	}
	copy := *c
	var err error
	copy.ClientSource, err = trimDirection(c.ClientSource, bounds[0])
	if err != nil {
		return err
	}
	copy.ServerSource, err = trimDirection(c.ServerSource, bounds[1])
	if err != nil {
		return err
	}
	copy.Source = core.MergedSource{Client: copy.ClientSource, Server: copy.ServerSource}
	clientHello, serverHello = prefix(copy.ClientSource), prefix(copy.ServerSource)
	if c.FragmentError != nil {
		return c.FragmentError
	}
	if clientHello == 0 && serverHello == 0 {
		return c.FragmentError
	}
	reader := &tlsReader{conversation: &copy, transportObservation: note}
	reader.frameTransportRun()
	return copy.FragmentError
}
