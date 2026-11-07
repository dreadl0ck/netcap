package enrichment

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/dreadl0ck/netcap/internal/servicesignatures"
)

// LoadServiceSignatures reads only the verified optional installation.
func LoadServiceSignatures(root string, trust ed25519.PublicKey, now time.Time) (*servicesignatures.Engine, error) {
	members, err := Open(root, trust, now)
	if err == nil {
		data, ok := members[servicesignatures.FileName]
		if !ok {
			err = fmt.Errorf("optional catalogue missing %s", servicesignatures.FileName)
		} else {
			var engine *servicesignatures.Engine
			engine, err = servicesignatures.Parse(bytes.NewReader(data))
			if err == nil {
				return engine, nil
			}
		}
	}
	return servicesignatures.Builtin(), fmt.Errorf("service signatures degraded: verified enrichment unavailable; using 4 builtins: %w", err)
}
