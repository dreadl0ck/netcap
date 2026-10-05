package resolvers

import (
	"testing"

	"github.com/dreadl0ck/netcap/internal/testutil"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func TestStructuredGeoContextAndPrivateUnknown(t *testing.T) {
	dir := geoTestDir(t)
	writeGeoProvider(t, dir, "dbip", map[string]mmdbtype.Map{"8.8.8.0/24": testutil.City("US", "fixture")}, map[string]mmdbtype.Map{"8.8.8.0/24": testutil.ASN(15169, "fixture")})
	CurrentConfig.GeoProviders = "dbip"
	if err := initGeolocationDB(); err != nil {
		t.Fatal(err)
	}
	context := LookupGeoContext("8.8.8.8")
	if context.Country != "US" || context.ASN != "15169" || len(context.Providers) != 1 || context.Providers[0] != "dbip" {
		t.Fatalf("context = %+v", context)
	}
	for _, ip := range []string{"192.168.1.1", "127.0.0.1", "fe80::1", "invalid", "198.51.100.1"} {
		if context := LookupGeoContext(ip); context.Country != "" || context.ASN != "" {
			t.Fatalf("unknown/private location fabricated: %+v", context)
		}
	}
}
