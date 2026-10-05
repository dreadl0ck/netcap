package resolvers

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

const DefaultGeoProviders = "dbip,geolite2"

type GeoProviderFiles struct {
	Name string
	City string
	ASN  string
}

var geoProviderFiles = []GeoProviderFiles{
	{"dbip", "dbip-city-lite.mmdb", "dbip-asn-lite.mmdb"},
	{"geolite2", "GeoLite2-City.mmdb", "GeoLite2-ASN.mmdb"},
}

func GeoFiles(name string) GeoProviderFiles {
	for _, p := range geoProviderFiles {
		if p.Name == name {
			return p
		}
	}
	return GeoProviderFiles{}
}

func ParseGeoProviders(raw string) ([]string, error) {
	var result []string
	seen := map[string]bool{}
	for _, name := range strings.Split(raw, ",") {
		name = strings.TrimSpace(name)
		if GeoFiles(name).Name == "" || seen[name] {
			return nil, fmt.Errorf("invalid geolocation provider order %q: use dbip and/or geolite2 once each", raw)
		}
		seen[name] = true
		result = append(result, name)
	}
	return result, nil
}

// Explicit CLI/config values override the environment, saved UI order and default.
func GeoProviderOrder(raw string) ([]string, error) {
	if raw == "" {
		raw = os.Getenv("NC_GEO_PROVIDERS")
	}
	if raw == "" {
		body, err := os.ReadFile(filepath.Join(ConfigRootPath, "geoip-settings.json"))
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		if err == nil {
			var settings struct {
				Providers string `json:"providers"`
			}
			if err := json.Unmarshal(body, &settings); err != nil {
				return nil, err
			}
			raw = settings.Providers
		}
	}
	if raw == "" {
		raw = DefaultGeoProviders
	}
	return ParseGeoProviders(raw)
}

func SaveGeoProviderOrder(raw string) error {
	order, err := ParseGeoProviders(raw)
	if err != nil {
		return err
	}
	body, err := json.Marshal(struct {
		Providers string `json:"providers"`
	}{strings.Join(order, ",")})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(ConfigRootPath, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(ConfigRootPath, ".geoip-settings-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(body); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(ConfigRootPath, "geoip-settings.json"))
}

func OpenGeoDatabase(path, provider, kind string) (*maxminddb.Reader, error) {
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	typeName := r.Metadata.DatabaseType
	want := "GeoLite2-" + kind
	if provider == "dbip" {
		want = "DBIP-" + kind + "-Lite"
	}
	if typeName != want && !(provider == "dbip" && kind == "ASN" && typeName == "DBIP-ASN-Lite (compat=GeoLite2-ASN)") {
		r.Close()
		return nil, fmt.Errorf("%s: expected %s, got %s", path, want, typeName)
	}
	return r, nil
}

type GeoProviderStatus struct {
	Name      string `json:"name"`
	Selected  bool   `json:"selected"`
	Available bool   `json:"available"`
	Loaded    bool   `json:"loaded"`
	CityFile  string `json:"cityFile"`
	ASNFile   string `json:"asnFile"`
	CityBuild string `json:"cityBuild,omitempty"`
	ASNBuild  string `json:"asnBuild,omitempty"`
	Error     string `json:"error,omitempty"`
}

func GeoProviderStatuses(raw string) ([]GeoProviderStatus, error) {
	order, err := GeoProviderOrder(raw)
	if err != nil {
		return nil, err
	}
	selected := map[string]bool{}
	for _, name := range order {
		selected[name] = true
	}
	var statuses []GeoProviderStatus
	for _, p := range geoProviderFiles {
		status := GeoProviderStatus{Name: p.Name, Selected: selected[p.Name], CityFile: p.City, ASNFile: p.ASN}
		city, err := OpenGeoDatabase(filepath.Join(DataBaseFolderPath, p.City), p.Name, "City")
		if err != nil {
			status.Error = err.Error()
		} else {
			status.CityBuild = time.Unix(int64(city.Metadata.BuildEpoch), 0).UTC().Format(time.RFC3339)
			city.Close()
		}
		asn, err := OpenGeoDatabase(filepath.Join(DataBaseFolderPath, p.ASN), p.Name, "ASN")
		if err != nil {
			status.Error += " " + err.Error()
		} else {
			status.ASNBuild = time.Unix(int64(asn.Metadata.BuildEpoch), 0).UTC().Format(time.RFC3339)
			asn.Close()
		}
		status.Error = strings.TrimSpace(status.Error)
		status.Available = status.Error == ""
		geoMu.RLock()
		for _, loaded := range geoProviders {
			if loaded.name == p.Name {
				status.Loaded = true
			}
		}
		geoMu.RUnlock()
		statuses = append(statuses, status)
	}
	return statuses, nil
}
