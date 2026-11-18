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

func firstSourceFragment(source core.FragmentSource, includeLink bool, budget *core.StateBudget, credit *int64) (data []byte, clientMAC, serverMAC string, err error) {
	// The connection lock keeps resident fragments valid through decoder selection.
	reader, resident := source.(*tcpStreamReader)
	resident = resident && (reader.stored == nil || reader.stored.loaded)
	var reserveErr error
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
		if data == nil {
			raw := fragment.Raw()
			if len(raw) == 0 {
				return true
			}
			if resident {
				data = raw[:len(raw):len(raw)]
				return includeLink && clientMAC == ""
			}
			n := int64(len(raw))
			if reserveErr = budget.Reserve(n); reserveErr != nil {
				return false
			}
			*credit += n
			data = bytes.Clone(raw)
		}
		return data == nil || includeLink && clientMAC == ""
	})
	if err == nil {
		err = reserveErr
	}
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
