//go:build hyperscan

/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package hsmatch

import (
	"fmt"
	"testing"
)

// BenchmarkMatch_SmallSet measures per-scan latency on a tiny pattern set
// (3 patterns) – this is the floor of HS overhead per call.
func BenchmarkMatch_SmallSet(b *testing.B) {
	db, _, err := Compile([]Pattern{
		{ID: 1, Expr: `foo`, Flags: FlagSingleMatch},
		{ID: 2, Expr: `BAR`, Flags: FlagCaseless | FlagSingleMatch},
		{ID: 3, Expr: `\d{3}`, Flags: FlagSingleMatch},
	})
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	buf := []byte("foo bar baz 4242 some longer banner content here")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = db.Match(buf, func(Hit) error { return nil })
	}
}

// BenchmarkMatch_LargeSet measures per-scan latency on 1000 patterns –
// the regime where HS multi-pattern compilation actually pays off.
func BenchmarkMatch_LargeSet(b *testing.B) {
	patterns := make([]Pattern, 0, 1000)
	for i := 0; i < 1000; i++ {
		patterns = append(patterns, Pattern{
			ID:    i,
			Expr:  fmt.Sprintf(`pattern_%d_\d+`, i),
			Flags: FlagSingleMatch,
		})
	}
	db, _, err := Compile(patterns)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	buf := []byte("the haystack contains pattern_42_1234 deep inside the buffer somewhere here")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = db.Match(buf, func(Hit) error { return nil })
	}
}

// BenchmarkMatch_LargeSet_NoMatch is the same compilation but a buffer
// guaranteed to miss every pattern – worst case for naive RE2 loops,
// best case for HS bulk scanning.
func BenchmarkMatch_LargeSet_NoMatch(b *testing.B) {
	patterns := make([]Pattern, 0, 1000)
	for i := 0; i < 1000; i++ {
		patterns = append(patterns, Pattern{
			ID:    i,
			Expr:  fmt.Sprintf(`pattern_%d_\d+`, i),
			Flags: FlagSingleMatch,
		})
	}
	db, _, err := Compile(patterns)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	buf := []byte("nothing here will match any of the configured patterns ever no way")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = db.Match(buf, func(Hit) error { return nil })
	}
}
