package collector

import (
	"io"
	"path/filepath"
	"slices"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
)

func TestOfflineBeaconRowsCorroborateEachOther(t *testing.T) {
	dc := config.DefaultConfig.Clone()
	dc.Out = t.TempDir()
	c := New(Config{DecoderConfig: dc, NetworkDetection: true})
	c.captureKind = "file"
	if err := c.initNetworkDetection(); err != nil {
		t.Fatal(err)
	}
	defer c.detachRecordAnalysis()

	beacon := func(recordType, dst string) *types.Alert {
		return &types.Alert{Name: "c2.beacon", RuleName: "c2.beacon", RecordType: recordType, SrcIP: "10.0.0.2", DstIP: dst, DstPort: "443", Tags: []string{"x"}}
	}
	if err := c.writeDetectionAlerts([]*types.Alert{beacon("NetworkDetection", "198.51.100.7"), beacon("NetworkDetection", "198.51.100.8")}); err != nil {
		t.Fatal(err)
	}
	if err := c.writeDetectionAlerts([]*types.Alert{beacon("ApplicationDetection", "198.51.100.7")}); err != nil {
		t.Fatal(err)
	}
	if err := c.closeNetworkDetection(); err != nil {
		t.Fatal(err)
	}

	r, err := netio.Open(filepath.Join(dc.Out, "Alert.ncap.gz"), 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.ReadHeader(); err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for {
		var a types.Alert
		if err := r.Next(&a); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		got[a.RecordType+"|"+a.DstIP] = a.Tags
	}
	if len(got) != 3 {
		t.Fatalf("rows lost or merged: %v", got)
	}
	if !slices.Contains(got["NetworkDetection|198.51.100.7"], "corroborated-by:ApplicationDetection") || !slices.Contains(got["ApplicationDetection|198.51.100.7"], "corroborated-by:NetworkDetection") {
		t.Fatalf("both detectors must mark each other: %v", got)
	}
	if slices.Contains(got["NetworkDetection|198.51.100.8"], "corroborated-by:ApplicationDetection") {
		t.Fatal("uncorroborated beacon was tagged")
	}
}
