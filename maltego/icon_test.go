package maltego

import (
	"github.com/dreadl0ck/netcap/encoder"
	"strings"
	"testing"
)

func TestGenerateAuditRecordIcons(t *testing.T) {

	generateIcons()

	encoder.ApplyActionToCustomEncoders(func(e *encoder.CustomEncoder) {
		generateAuditRecordIcon(e.Name)
	})

	encoder.ApplyActionToLayerEncoders(func(e *encoder.LayerEncoder) {
		name := strings.ReplaceAll(e.Layer.String() ,"/", "")
		generateAuditRecordIcon(name)
	})
}
