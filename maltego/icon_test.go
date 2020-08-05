package maltego

import (
	"fmt"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/decoder"
)

// deprecated, use V2
//func TestGenerateAuditRecordIcons(t *testing.T) {
//
//	generateIcons()
//
//	decoder.ApplyActionToCustomDecoders(func(e *decoder.CustomDecoder) {
//		generateAuditRecordIcon(e.Name)
//	})
//
//	decoder.ApplyActionToGoPacketDecoders(func(e *decoder.GoPacketDecoder) {
//		name := strings.ReplaceAll(e.Layer.String(), "/", "")
//		generateAuditRecordIcon(name)
//	})
//}

func TestGenerateAuditRecordIconsV2(t *testing.T) {
	if !generateMaltegoConfig {
		return
	}

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
