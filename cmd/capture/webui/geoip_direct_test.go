//go:build !appstore

package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/resolvers"
)

func TestGeoProviderSettingsPersistAndValidate(t *testing.T) {
	root := resolvers.ConfigRootPath
	resolvers.ConfigRootPath = t.TempDir()
	t.Cleanup(func() { resolvers.ConfigRootPath = root })
	withEmptyDatabaseDir(t)
	t.Setenv("NC_GEO_PROVIDERS", "")
	s := &Server{runtimeConfig: &RuntimeConfig{GeoProviders: "dbip"}}
	rec := httptest.NewRecorder()
	s.handleGeoProviders(rec, httptest.NewRequest(http.MethodPost, "/api/dbs/geoip", strings.NewReader(`{"providers":"geolite2,dbip"}`)))
	if rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	var status DatabaseStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.GeoProviders != "geolite2,dbip" || len(status.GeoStatus) != 2 {
		t.Fatal(status)
	}
	if s.geoProviderSelection() != "geolite2,dbip" {
		t.Fatal("override not applied")
	}
	order, err := resolvers.GeoProviderOrder("")
	if err != nil || strings.Join(order, ",") != "geolite2,dbip" {
		t.Fatal("not persisted", order, err)
	}
	rec = httptest.NewRecorder()
	s.handleGeoProviders(rec, httptest.NewRequest(http.MethodPost, "/api/dbs/geoip", strings.NewReader(`{"providers":"dbip,unknown"}`)))
	if rec.Code != 400 || s.geoProviderSelection() != "geolite2,dbip" {
		t.Fatal("invalid settings changed order", rec.Code)
	}
}
