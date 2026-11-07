package firewallstate

import (
	"encoding/json"
	"slices"
	"time"
)

var statePostgresSchema = []string{
	`CREATE TABLE IF NOT EXISTS metadata(version INTEGER NOT NULL)`,
	`INSERT INTO metadata SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM metadata)`,
	`CREATE TABLE IF NOT EXISTS counters(tenant TEXT NOT NULL,app TEXT NOT NULL,revision TEXT NOT NULL,grp TEXT NOT NULL,duration BIGINT NOT NULL,count BIGINT NOT NULL,expires BIGINT NOT NULL,PRIMARY KEY(tenant,app,revision,grp))`,
	`CREATE TABLE IF NOT EXISTS counter_clock(id INTEGER PRIMARY KEY CHECK(id=1),last_ns BIGINT NOT NULL)`,
	`INSERT INTO counter_clock SELECT 1,coalesce(max(expires-duration),0) FROM counters ON CONFLICT(id) DO NOTHING`,
}

func stateFingerprint(cfg Config) string {
	principals := append([]Principal(nil), cfg.Principals...)
	for i := range principals {
		principals[i].Token = Digest(principals[i].Token)
	}
	slices.SortFunc(principals, func(a, b Principal) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	raw, _ := json.Marshal(struct {
		Service              string
		Version, MaxKeys     int
		Principals           []Principal
		MaxWindow, MinWindow int64
	}{"sharedstate", 1, cfg.MaxKeys, principals, int64(MaxWindow), int64(time.Millisecond)})
	return Digest(string(raw))
}
