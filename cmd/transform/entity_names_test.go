package transform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGoPacketEntityNamesFollowWriterFiles(t *testing.T) {
	names := goPacketEntityNames()
	for file, entity := range map[string]string{"GTP": "GTPv1U", "VRRP": "VRRP", "ApplePktap": "ApplePktap"} {
		if names[file] != entity {
			t.Errorf("%s.ncap.gz maps to entity %q, want %q", file, names[file], entity)
		}
	}
	for file, entity := range names {
		if entity == "ApplePktap" {
			continue // PKTAP has never had a Maltego entity.
		}
		path := filepath.Join("..", "..", "internal", "maltego", "netcap", "Entities", "netcap."+entity+"AuditRecords.entity")
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s.ncap.gz has no AuditRecords entity: %v", file, err)
		}
	}
}
