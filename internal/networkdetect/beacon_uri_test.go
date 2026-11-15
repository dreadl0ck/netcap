package networkdetect

import (
	"fmt"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/types"
)

func TestBeaconURIsShareOneIncidentWithoutSharingCadence(t *testing.T) {
	e := NewApplication(DefaultConfig())
	var alerts []*types.Alert
	for i := 0; i < 20; i++ {
		for path := 0; path < 2; path++ {
			o := httpObservation(i*30 + path)
			o.Status = 200
			o.Path = fmt.Sprintf("/periodic-%d", path)
			alerts = append(alerts, e.Observe(o)...)
		}
	}
	alerts = append(alerts, e.Flush()...)
	var beacons []*types.Alert
	for _, a := range alerts {
		if a.Name == "c2.beacon" {
			beacons = append(beacons, a)
		}
	}
	if len(beacons) != 1 || len(beacons[0].Examples) < 2 || !strings.Contains(strings.Join(beacons[0].Examples, " "), "periodic-") {
		t.Fatal(beacons)
	}
	if len(e.beacons) != 2 {
		t.Fatal("URI timing series were incorrectly merged")
	}
}
