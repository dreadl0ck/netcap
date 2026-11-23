package packet

import (
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/auditname"
)

// Every file a gopacket decoder writes must resolve back to its record type,
// or readers that check the audit header treat it as mislabeled.
func TestAuditNameTableCoversGoPacketDecoders(t *testing.T) {
	if len(defaultGoPacketDecoders) == 0 {
		t.Fatal("no gopacket decoders registered")
	}
	for _, dec := range defaultGoPacketDecoders {
		base := dec.AuditFileBase()
		want := strings.TrimPrefix(dec.Type.String(), "NC_")
		if got := auditname.TypeForFile(base); got != want {
			t.Errorf("%s writes %s.ncap.gz, which resolves to %q", want, base, got)
		}
		found := false
		for _, candidate := range auditname.FileBases(want) {
			found = found || candidate == base
		}
		if !found {
			t.Errorf("readers of %s never open %s.ncap.gz", want, base)
		}
	}
}
