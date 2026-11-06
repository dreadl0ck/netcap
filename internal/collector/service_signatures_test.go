package collector

import (
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/service"
	"github.com/dreadl0ck/netcap/internal/servicesignatures"
)

func TestServiceInventoryFollowsInitializedDecoders(t *testing.T) {
	c := New(ultimateCaptureConfig(t.TempDir(), 1, 0))
	// Excluded/uninitialized Service must not inherit another run's loaded state.
	if err := c.persistServiceSignatures(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.config.DecoderConfig.Out, servicesignatures.InventoryFileName)
	i, err := servicesignatures.ReadInventory(path)
	if err != nil || i.State != "disabled" || i.RuleCount != 0 {
		t.Fatalf("%+v %v", i, err)
	}
	c.abstractDecoders = []core.DecoderAPI{service.Decoder}
	if err := c.persistServiceSignatures(); err != nil {
		t.Fatal(err)
	}
	i, err = servicesignatures.ReadInventory(path)
	if err != nil || i.State != service.SignatureInventory().State {
		t.Fatalf("%+v %v", i, err)
	}
}
