package policystate

import (
	"bytes"
	"context"
	"testing"

	"github.com/dreadl0ck/netcap/internal/policy"
)

func TestPersistedRowInvariantsMatchStartupAndRuntime(t *testing.T) {
	for _, corruption := range []string{"zero", "negative", "fresh", "fresh-positive-row", "future", "expiry", "scope", "revision", "artifact"} {
		t.Run(corruption, func(t *testing.T) {
			s := store(t, config(t))
			p := descriptor(t, "validated", "fixed", "", 2)
			ctx := context.Background()
			req := request(p, policy.Event{ClientIP: "one"})
			if _, err := s.Evaluate(ctx, testScope, req); err != nil {
				t.Fatal(err)
			}
			var clock int64
			if err := s.disk.DB.QueryRow(`SELECT last_ns FROM policy_state_meta`).Scan(&clock); err != nil {
				t.Fatal(err)
			}
			var query string
			var args []any
			switch corruption {
			case "zero":
				query = `UPDATE policy_states SET watermark=0`
			case "negative":
				query = `UPDATE policy_states SET watermark=-1`
			case "future":
				query, args = `UPDATE policy_states SET watermark=?`, []any{clock + 1}
			case "expiry":
				query = `UPDATE policy_states SET expires=watermark-1`
			case "scope":
				query = `UPDATE policy_states SET tenant='unauthorized'`
			case "revision":
				query = `UPDATE policy_states SET revision='invalid'`
			case "artifact":
				query = `UPDATE policy_states SET bundle=cast(' ' AS BLOB)||bundle`
			case "fresh", "fresh-positive-row":
				fresh := p.Fork()
				raw, err := fresh.ExportState(ctx)
				if err != nil {
					t.Fatal(err)
				}
				query, args = `UPDATE policy_states SET snapshot=?,accounted=?`, []any{raw, fresh.StateProgramBytes()}
				if corruption == "fresh" {
					query += `,watermark=?,expires=?`
					args = append(args, fresh.StateWatermark().UnixNano(), fresh.StateDeadline().UnixNano())
				}
			}
			if _, err := s.disk.DB.Exec(query, args...); err != nil {
				t.Fatal(err)
			}
			var before []byte
			if err := s.disk.DB.QueryRow(`SELECT snapshot FROM policy_states`).Scan(&before); err != nil {
				t.Fatal(err)
			}
			tx, err := s.disk.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			validationErr := s.validate(ctx, tx)
			_ = tx.Rollback()
			if validationErr == nil {
				t.Fatal("startup validation accepted corrupted row")
			}
			if d, err := s.Evaluate(ctx, testScope, req); err == nil || d.Verdict != "" {
				t.Fatal("runtime validation accepted corrupted row", d, err)
			}
			var after []byte
			var afterClock int64
			if err := s.disk.DB.QueryRow(`SELECT snapshot FROM policy_states`).Scan(&after); err != nil {
				t.Fatal(err)
			}
			if err := s.disk.DB.QueryRow(`SELECT last_ns FROM policy_state_meta`).Scan(&afterClock); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) || clock != afterClock {
				t.Fatal("failed validation changed persisted state or clock")
			}
		})
	}
}
