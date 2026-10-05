package resolvers

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/testutil"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func geoTestDir(t *testing.T) string {
	t.Helper()
	originalDir, originalRoot, config := DataBaseFolderPath, ConfigRootPath, CurrentConfig
	dir := t.TempDir()
	DataBaseFolderPath, ConfigRootPath = dir, dir
	CurrentConfig.GeoProviders = "dbip,geolite2"
	t.Setenv("NC_GEO_PROVIDERS", "")
	t.Cleanup(func() {
		geoMu.Lock()
		closeGeoProviders()
		geoMu.Unlock()
		DataBaseFolderPath, ConfigRootPath, CurrentConfig = originalDir, originalRoot, config
	})
	return dir
}

func writeGeoProvider(t *testing.T, dir, name string, city, asn map[string]mmdbtype.Map) {
	t.Helper()
	files := GeoFiles(name)
	cityType, asnType := "GeoLite2-City", "GeoLite2-ASN"
	if name == "dbip" {
		cityType, asnType = "DBIP-City-Lite", "DBIP-ASN-Lite (compat=GeoLite2-ASN)"
	}
	testutil.WriteMMDB(t, filepath.Join(dir, files.City), cityType, time.Now(), city)
	testutil.WriteMMDB(t, filepath.Join(dir, files.ASN), asnType, time.Now(), asn)
}

func TestGeoProvidersOrderAndFallback(t *testing.T) {
	dir := geoTestDir(t)
	writeGeoProvider(t, dir, "dbip", map[string]mmdbtype.Map{"8.8.8.0/24": testutil.City("US", "DB-IP city")}, map[string]mmdbtype.Map{"1.1.1.0/24": testutil.ASN(13335, "DB-IP org")})
	writeGeoProvider(t, dir, "geolite2", map[string]mmdbtype.Map{"8.8.8.0/24": testutil.City("CA", "GeoLite city"), "1.1.1.0/24": testutil.City("AU", "Sydney")}, map[string]mmdbtype.Map{"8.8.8.0/24": testutil.ASN(15169, "Google")})
	for _, tc := range []struct{ order, ip, loc, asn string }{
		{"dbip,geolite2", "8.8.8.8", "US (DB-IP city)", "ASN 15169 (Google)"},
		{"geolite2,dbip", "8.8.8.8", "CA (GeoLite city)", "ASN 15169 (Google)"},
		{"dbip,geolite2", "1.1.1.1", "AU (Sydney)", "ASN 13335 (DB-IP org)"},
		{"dbip", "8.8.8.8", "US (DB-IP city)", ""},
		{"geolite2", "1.1.1.1", "AU (Sydney)", ""},
	} {
		CurrentConfig.GeoProviders = tc.order
		if err := initGeolocationDB(); err != nil {
			t.Fatal(err)
		}
		loc, asn := LookupGeolocation(tc.ip)
		if loc != tc.loc || asn != tc.asn {
			t.Fatalf("%s %s: (%s,%s), want (%s,%s)", tc.order, tc.ip, loc, asn, tc.loc, tc.asn)
		}
	}
}

func TestGeoProvidersSkipMissingOrInvalidSelectedProvider(t *testing.T) {
	dir := geoTestDir(t)
	writeGeoProvider(t, dir, "geolite2", map[string]mmdbtype.Map{"8.8.8.0/24": testutil.City("US", "Valid")}, map[string]mmdbtype.Map{"8.8.8.0/24": testutil.ASN(1, "Valid")})
	if err := initGeolocationDB(); err != nil {
		t.Fatal(err)
	}
	if loc, _ := LookupGeolocation("8.8.8.8"); loc != "US (Valid)" {
		t.Fatal(loc)
	}
	testutil.WriteMMDB(t, filepath.Join(dir, GeoFiles("dbip").City), "Wrong-Type", time.Now(), nil)
	testutil.WriteMMDB(t, filepath.Join(dir, GeoFiles("dbip").ASN), "DBIP-ASN-Lite", time.Now(), nil)
	if err := initGeolocationDB(); err != nil {
		t.Fatal(err)
	}
	CurrentConfig.GeoProviders = "dbip"
	if err := initGeolocationDB(); err == nil || !strings.Contains(err.Error(), "Wrong-Type") {
		t.Fatalf("wrong provider accepted: %v", err)
	}
	if loc, _ := LookupGeolocation("8.8.8.8"); loc != "" {
		t.Fatal("retained old provider", loc)
	}
}

func TestDBIPIPv6Fallback(t *testing.T) {
	dir := geoTestDir(t)
	writeGeoProvider(t, dir, "dbip", map[string]mmdbtype.Map{"2000::/3": testutil.City("CH", "Murten/Morat")}, nil)
	writeGeoProvider(t, dir, "geolite2", map[string]mmdbtype.Map{"2001:4860::/32": testutil.City("US", "Google")}, nil)
	if err := initGeolocationDB(); err != nil {
		t.Fatal(err)
	}
	if loc, _ := LookupGeolocation("2001:4860::1"); loc != "US (Google)" {
		t.Fatal(loc)
	}
	if loc, _ := LookupGeolocation("3fff::1"); loc != "" {
		t.Fatal("bogus fallback", loc)
	}
	if usableDBIPLocation(net.ParseIP("4000::1"), 1) {
		t.Fatal("non-global allocated IPv6 space accepted")
	}
}

func TestGeoProviderSettingsValidationAndPrecedence(t *testing.T) {
	geoTestDir(t)
	for _, bad := range []string{"", "dbip,dbip", "unknown", "dbip,"} {
		if _, err := ParseGeoProviders(bad); err == nil {
			t.Fatal("accepted", bad)
		}
	}
	if err := SaveGeoProviderOrder("geolite2,dbip"); err != nil {
		t.Fatal(err)
	}
	order, err := GeoProviderOrder("")
	if err != nil || strings.Join(order, ",") != "geolite2,dbip" {
		t.Fatal(order, err)
	}
	t.Setenv("NC_GEO_PROVIDERS", "dbip")
	order, _ = GeoProviderOrder("")
	if strings.Join(order, ",") != "dbip" {
		t.Fatal(order)
	}
	order, _ = GeoProviderOrder("geolite2")
	if strings.Join(order, ",") != "geolite2" {
		t.Fatal(order)
	}
	if err := SaveGeoProviderOrder("invalid"); err == nil {
		t.Fatal("invalid settings saved")
	}
	body, _ := os.ReadFile(filepath.Join(ConfigRootPath, "geoip-settings.json"))
	if !strings.Contains(string(body), "geolite2,dbip") {
		t.Fatal(string(body))
	}
}
