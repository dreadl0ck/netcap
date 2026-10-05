package testutil

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func WriteMMDB(t testing.TB, path, kind string, month time.Time, records map[string]mmdbtype.Map) {
	t.Helper()
	tree, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: kind, BuildEpoch: month.Unix(), IncludeReservedNetworks: true, Languages: []string{"en"}, Description: map[string]string{"en": "Synthetic test database"}})
	if err != nil {
		t.Fatal(err)
	}
	for prefix, record := range records {
		_, network, err := net.ParseCIDR(prefix)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.Insert(network, record); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tree.WriteTo(f)
	closeErr := f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
}

func City(country, city string) mmdbtype.Map {
	return mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String(country)}, "city": mmdbtype.Map{"names": mmdbtype.Map{"en": mmdbtype.String(city)}}}
}

func ASN(number uint32, org string) mmdbtype.Map {
	return mmdbtype.Map{"autonomous_system_number": mmdbtype.Uint32(number), "autonomous_system_organization": mmdbtype.String(org)}
}
