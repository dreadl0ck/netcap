package stream

import (
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	decoderutils "github.com/dreadl0ck/netcap/internal/decoder/utils"
)

// Service DeInit emits signature Software and its vulnerability and exploit
// lookups. Those must run before Exploit DeInit closes the exploit index and
// before Software DeInit writes and closes the vulnerability index, including
// after -include/-exclude selection.
func TestServiceFlushesBeforeSoftwareConsumers(t *testing.T) {
	for _, include := range []string{"", "Vulnerability,Software,Exploit,Service"} {
		active, err := decoderutils.SelectDecoders(DefaultAbstractDecoders, include, "", func(d core.DecoderAPI) string { return d.GetName() }, errInvalidAbstractDecoder)
		if err != nil {
			t.Fatal(err)
		}
		position := map[string]int{}
		for i, d := range active {
			position[d.GetName()] = i
		}
		for _, later := range []string{"Exploit", "Software", "Vulnerability"} {
			if position["Service"] >= position[later] {
				t.Fatalf("include=%q: Service at %d, %s at %d", include, position["Service"], later, position[later])
			}
		}
	}
}
