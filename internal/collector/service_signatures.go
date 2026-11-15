package collector

import (
	"encoding/json"
	"fmt"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/service"
	"github.com/dreadl0ck/netcap/internal/enrichment"
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/internal/servicesignatures"
	"github.com/dreadl0ck/netcap/types"
	"os"
	"path/filepath"
	"time"
)

func (c *Collector) persistServiceSignatures() error {
	if c.config.DecoderConfig.Out == "" {
		return nil
	}
	i := servicesignatures.UnavailableInventory("disabled", "Service decoder was not initialized for this capture")
	for _, d := range c.abstractDecoders {
		if d.GetType() == types.Type_NC_Service {
			i = service.SignatureInventory()
			break
		}
	}
	if err := servicesignatures.WriteInventory(c.config.DecoderConfig.Out, i); err != nil {
		return err
	}
	snapshot := enrichment.Inspect(enrichment.Root(resolvers.ConfigRootPath), enrichment.SigningRoot(), time.Now())
	c.enrichmentSnapshot = &snapshot
	if snapshot.State == "stale" {
		fmt.Fprintf(os.Stderr, "enrichment release %s expired at %s; using reverified offline snapshot\n", snapshot.ReleaseSHA256, time.Unix(snapshot.ExpiresAt, 0).UTC().Format(time.RFC3339))
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(c.config.DecoderConfig.Out, "enrichment-status.json"), append(data, '\n'), 0600)
}
