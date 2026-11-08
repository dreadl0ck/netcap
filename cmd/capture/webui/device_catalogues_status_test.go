//go:build !appstore

package webui

import (
	"encoding/json"
	"testing"
)

func TestDeviceAttributionInDatabaseSummary(t *testing.T) {
	withEmptyDatabaseDir(t)
	body, err := json.Marshal(currentDatabaseStatus())
	if err != nil {
		t.Fatal(err)
	}
	var summary struct {
		Devices []struct {
			Kind        string `json:"kind"`
			Attribution string `json:"attribution"`
			Source      string `json:"source_url"`
			License     string `json:"license_url"`
			Notices     string `json:"notices_file"`
		} `json:"deviceCatalogues"`
	}
	if err = json.Unmarshal(body, &summary); err != nil {
		t.Fatal(err)
	}
	if len(summary.Devices) != 2 {
		t.Fatal(string(body))
	}
	for _, device := range summary.Devices {
		if device.Attribution == "" || device.Source == "" || device.License == "" || device.Notices != "ENRICHMENT_NOTICES.txt" {
			t.Fatalf("%+v", device)
		}
	}
}
