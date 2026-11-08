package webui

import (
	"os"
	"time"

	"github.com/dreadl0ck/netcap/internal/enrichment"
	"github.com/dreadl0ck/netcap/internal/resolvers"
)

func attachKEV(result *VulnerabilitiesResponse) {
	result.KEVStatus = "unavailable"
	root, e := catalogueSigningRoot()
	if e != nil {
		return
	}
	members, e := enrichment.Open(enrichment.Root(resolvers.ConfigRootPath), root, time.Now())
	if e != nil {
		if !os.IsNotExist(e) {
			result.KEVStatus = "invalid-or-stale"
		}
		return
	}
	b, ok := members["kev.json"]
	if !ok {
		return
	}
	catalog, e := enrichment.ParseKEV(b)
	if e != nil {
		result.KEVStatus = "invalid-or-stale"
		return
	}
	result.KEVStatus = "available"
	for i := range result.Vulnerabilities {
		result.Vulnerabilities[i].KEV = catalog.Lookup(result.Vulnerabilities[i].ID)
	}
}
