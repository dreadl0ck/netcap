// +build icons

package maltego

import (
	"fmt"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/decoder"
)

func TestGenerateAuditRecordIcons(t *testing.T) {
	generateIcons()

	decoder.ApplyActionToCustomDecoders(func(d decoder.CustomDecoderAPI) {
		fmt.Println(d.GetName())
		generateAuditRecordIconV2(d.GetName())
	})

	decoder.ApplyActionToGoPacketDecoders(func(e *decoder.GoPacketDecoder) {
		name := strings.ReplaceAll(e.Layer.String(), "/", "")
		fmt.Println(name)
		generateAuditRecordIconV2(name)
	})
}
