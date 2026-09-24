package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeMap(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "points.csv")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestDNP3PointMapAcceptsValidFile(t *testing.T) {
	path := writeMap(t, "# outstation,group,index,name\n\n3,12,7,Feeder 4 breaker\n3,12,8,Feeder 5 breaker\n")

	if err := (&Config{DNP3PointMap: path}).ValidateDNP3PointMap(); err != nil {
		t.Fatal(err)
	}

	points, err := parseDNP3PointMap(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := points[DNP3Point{Outstation: 3, Group: 12, Index: 7}]; got != "Feeder 4 breaker" {
		t.Errorf("point name = %q", got)
	}
	if len(points) != 2 {
		t.Errorf("parsed %d points, want 2", len(points))
	}
}

func TestDNP3PointMapEmptyIsOff(t *testing.T) {
	c := &Config{}
	if err := c.ValidateDNP3PointMap(); err != nil {
		t.Fatal(err)
	}
	if got := c.DNP3PointName(3, 12, 7); got != "" {
		t.Errorf("point name = %q, want empty", got)
	}
}

// A bad file must fail decoder initialisation. Silently leaving every point
// unnamed looks identical to an outstation nobody mapped.
func TestDNP3PointMapRejectsBadInput(t *testing.T) {
	for name, body := range map[string]string{
		"too few fields":   "3,12,7\n",
		"not a number":     "3,twelve,7,Feeder\n",
		"group too wide":   "3,300,7,Feeder\n",
		"outstation wide":  "70000,12,7,Feeder\n",
		"empty name":       "3,12,7,\n",
		"conflicting name": "3,12,7,Feeder 4\n3,12,7,Feeder 9\n",
	} {
		t.Run(name, func(t *testing.T) {
			if err := (&Config{DNP3PointMap: writeMap(t, body)}).ValidateDNP3PointMap(); err == nil {
				t.Error("accepted invalid point map")
			}
		})
	}
}

func TestDNP3PointMapRejectsMissingFile(t *testing.T) {
	if err := (&Config{DNP3PointMap: "/nonexistent/points.csv"}).ValidateDNP3PointMap(); err == nil {
		t.Error("accepted a missing point map")
	}
}

// Repeating the same name for the same point is a duplicate, not a conflict.
func TestDNP3PointMapAllowsIdenticalDuplicate(t *testing.T) {
	if err := (&Config{DNP3PointMap: writeMap(t, "3,12,7,Feeder 4\n3,12,7,Feeder 4\n")}).ValidateDNP3PointMap(); err != nil {
		t.Errorf("rejected an identical duplicate: %v", err)
	}
}
