package tcp

import (
	"bytes"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/gopacket/gopacket"
)

func readerFragments(reader streamReader) core.FragmentSource {
	if source, ok := reader.(core.FragmentSource); ok {
		return source
	}
	return core.SliceSource(reader.DataSlice())
}

func firstSourceFragment(source core.FragmentSource, includeLink bool) (data []byte, clientMAC, serverMAC string, err error) {
	err = source.Walk(func(fragment core.DataFragment) bool {
		if fragment == nil {
			return true
		}
		if includeLink && clientMAC == "" {
			if context, ok := fragment.Context().(interface{ GetLinkFlow() gopacket.Flow }); ok {
				flow := context.GetLinkFlow()
				if len(flow.Src().Raw()) > 0 {
					clientMAC, serverMAC = flow.Src().String(), flow.Dst().String()
				}
			}
		}
		if data == nil && len(fragment.Raw()) > 0 {
			data = bytes.Clone(fragment.Raw())
		}
		return data == nil || includeLink && clientMAC == ""
	})
	return
}

func readerDataResult(reader streamReader) (core.DataFragments, error) {
	if source, ok := reader.(interface {
		DataSliceResult() (core.DataFragments, error)
	}); ok {
		return source.DataSliceResult()
	}
	return reader.DataSlice(), nil
}

func (t *tcpConnection) fragmentSource() core.FragmentSource {
	t.Lock()
	defer t.Unlock()
	return core.MergedSource{Client: readerFragments(t.client), Server: readerFragments(t.server)}
}
