package collector

import (
	"github.com/dreadl0ck/netcap/internal/decoder/stream/service"
	"github.com/dreadl0ck/netcap/internal/servicesignatures"
	"github.com/dreadl0ck/netcap/types"
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
	return servicesignatures.WriteInventory(c.config.DecoderConfig.Out, i)
}
