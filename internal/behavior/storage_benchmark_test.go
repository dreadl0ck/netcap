package behavior

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func benchmarkBaseline(facts int) Snapshot {
	state := Snapshot{Schema: SchemaVersion, Mode: Learning, MinLearningNS: 1, MinSamples: 2, MaxFacts: facts,
		LearningStarted: 1700000000000000000, Watermark: 1700000001000000000, Samples: 2,
		Observed: map[string]Observation{}, Approved: map[string]Fact{}, Suppressed: map[string]string{},
		Activity: map[string]Activity{}, Policy: DefaultPolicy(), Rates: map[string]RateStats{}, ApprovedRates: map[string]RateModel{},
		Labels: map[string]AssetLabel{}, Corrections: map[string]Fact{}, Leases: map[string]Lease{}}
	for i := range facts {
		fact := Fact{Scope: Scope{Sensor: "benchmark", Interface: "pcap"}, Kind: "device", MAC: fmt.Sprintf("02:00:%02x:%02x:%02x:%02x", byte(i>>24), byte(i>>16), byte(i>>8), byte(i))}
		state.Observed[factID(fact)] = Observation{Fact: fact, FirstSeen: state.LearningStarted, LastSeen: state.Watermark, Samples: 2}
	}
	return state
}

// The row-update case is an optimistic SQLite lower bound, not a complete state-store implementation.
func BenchmarkBaselineDurableStorage(b *testing.B) {
	for _, facts := range []int{1000, 10000} {
		b.Run(fmt.Sprint(facts), func(b *testing.B) {
			b.Run("atomic-json-checkpoint", func(b *testing.B) {
				state := benchmarkBaseline(facts)
				path := filepath.Join(b.TempDir(), "Behavior.json")
				b.ResetTimer()
				for range b.N {
					state.Samples++
					if err := writeSnapshot(path, state); err != nil {
						b.Fatal(err)
					}
				}
				b.StopTimer()
				got, err := ReadSnapshot(path)
				if err != nil || len(got.Observed) != facts || got.Samples != state.Samples {
					b.Fatalf("checkpoint not retained: %v", err)
				}
			})
			for _, incremental := range []bool{false, true} {
				name := "sqlite-wal-full-checkpoint"
				if incremental {
					name = "sqlite-wal-one-row-commit"
				}
				b.Run(name, func(b *testing.B) {
					state := benchmarkBaseline(facts)
					db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(b.TempDir(), "baseline.sqlite"))+"?_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)")
					if err != nil {
						b.Fatal(err)
					}
					defer db.Close()
					db.SetMaxOpenConns(1)
					if _, err := db.Exec("CREATE TABLE baseline (id TEXT PRIMARY KEY, data BLOB NOT NULL)"); err != nil {
						b.Fatal(err)
					}
					data, err := json.Marshal(state)
					if err != nil {
						b.Fatal(err)
					}
					if _, err := db.Exec("INSERT INTO baseline VALUES ('snapshot', ?)", data); err != nil {
						b.Fatal(err)
					}
					if incremental {
						tx, err := db.Begin()
						if err != nil {
							b.Fatal(err)
						}
						for id, observation := range state.Observed {
							data, err := json.Marshal(observation)
							if err != nil {
								b.Fatal(err)
							}
							if _, err := tx.Exec("INSERT INTO baseline VALUES (?, ?)", id, data); err != nil {
								b.Fatal(err)
							}
						}
						if err := tx.Commit(); err != nil {
							b.Fatal(err)
						}
					}
					var id string
					var observation Observation
					for key, value := range state.Observed {
						id, observation = key, value
						break
					}
					b.ResetTimer()
					for range b.N {
						key := "snapshot"
						if incremental {
							key = id
							observation.Samples++
							data, err = json.Marshal(observation)
						} else {
							state.Samples++
							data, err = json.Marshal(state)
						}
						if err != nil {
							b.Fatal(err)
						}
						if _, err := db.Exec("UPDATE baseline SET data=? WHERE id=?", data, key); err != nil {
							b.Fatal(err)
						}
					}
					b.StopTimer()
					key := "snapshot"
					if incremental {
						key = id
					}
					var stored []byte
					if err := db.QueryRow("SELECT data FROM baseline WHERE id=?", key).Scan(&stored); err != nil {
						b.Fatal(err)
					}
					if string(stored) != string(data) {
						b.Fatal("SQLite update was not retained")
					}
				})
			}
		})
	}
}
