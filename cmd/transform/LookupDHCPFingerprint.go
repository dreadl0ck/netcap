package transform

import (
	"fmt"
	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/internal/resolvers"
)

func lookupDHCPFingerprint() {
	trx := &maltego.Transform{}
	trx.AddUIMessage(resolvers.ErrDHCPEnrichmentDisabled.Error(), maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
