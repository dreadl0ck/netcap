package maltego

import (
	"fmt"
	"github.com/dreadl0ck/netcap/decoder"
	"strings"
	"testing"
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
//	decoder.ApplyActionToLayerDecoders(func(e *decoder.GoPacketDecoder) {
//		name := strings.ReplaceAll(e.Layer.String(), "/", "")
//		generateAuditRecordIcon(name)
//	})
//}

func TestGenerateAuditRecordIconsV2(t *testing.T) {

	if !generateMaltegoConfig {
		return
	}

	generateIcons()

	decoder.ApplyActionToCustomDecoders(func(e *decoder.CustomDecoder) {
		fmt.Println(e.Name)
		generateAuditRecordIconV2(e.Name)
	})

	decoder.ApplyActionToLayerDecoders(func(e *decoder.GoPacketDecoder) {
		name := strings.ReplaceAll(e.Layer.String(), "/", "")
		fmt.Println(name)
		generateAuditRecordIconV2(name)
	})
}
