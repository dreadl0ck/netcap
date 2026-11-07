//go:build !appstore

package webui

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/servicesignatures"
	"github.com/dreadl0ck/netcap/internal/webtech/testfixture"
)

func TestInstalledServiceCatalogueAgreesWithCaptureAdmission(t *testing.T) {
	fixture, err := testfixture.Build()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "enrichment")
	if err := fixture.Install(root); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(fixture.Now, 0)
	response := serviceSignatureCatalogue(root, fixture.Trust, now)
	if response["degraded"] != false || response["source"] != "external" {
		t.Fatal(response)
	}
	inventory := response["inventory"].(servicesignatures.Inventory)
	if inventory.Degraded || inventory.Source != "external" || inventory.SourceSHA256 == "" || inventory.Scope != "installed-catalogue" {
		t.Fatal(inventory)
	}
	if !reflect.DeepEqual(response["catalogue"], *inventory.Catalogue) {
		t.Fatal("inventory differs from served catalogue")
	}
	if err := os.WriteFile(filepath.Join(root, "active"), []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	response = serviceSignatureCatalogue(root, fixture.Trust, now)
	if response["degraded"] != true || response["source"] != "builtin" {
		t.Fatal("invalid installation accepted", response)
	}
}
