package firewallfleet

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/dreadl0ck/netcap/internal/firewallstate"
)

var fleetPostgresSchema = []string{
	`CREATE TABLE IF NOT EXISTS fleet(id INTEGER PRIMARY KEY CHECK(id=1),snapshot BYTEA NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS artifacts(key TEXT PRIMARY KEY,tenant TEXT NOT NULL,app TEXT NOT NULL,revision TEXT NOT NULL,bundle BYTEA NOT NULL)`,
}

func fleetFingerprint(cfg Config) string {
	identities := append([]Identity(nil), cfg.Identities...)
	targets := append([]Enrollment(nil), cfg.Targets...)
	for i := range identities {
		identities[i].Token = firewallstate.Digest(identities[i].Token)
	}
	for i := range targets {
		targets[i].Token = firewallstate.Digest(targets[i].Token)
	}
	slices.SortFunc(identities, func(a, b Identity) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(targets, func(a, b Enrollment) int { return strings.Compare(a.ID, b.ID) })
	raw, _ := json.Marshal(struct {
		Service                         string
		Version                         int
		Token                           string
		Identities                      []Identity
		Targets                         []Enrollment
		AllowEffects, RollbackOnFailure bool
		Limits                          [7]int
	}{"fleet", 1, firewallstate.Digest(cfg.Token), identities, targets, cfg.AllowEffects, cfg.RollbackOnFailure, [7]int{MaxTargets, MaxRevisions, MaxJobs, MaxAudit, MaxArtifactBytes, MaxRequestBytes, MaxSnapshotBytes}})
	return firewallstate.Digest(string(raw))
}
