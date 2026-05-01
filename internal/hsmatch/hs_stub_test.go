//go:build !hyperscan

/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package hsmatch

import (
	"errors"
	"testing"
)

func TestStubReturnsDisabled(t *testing.T) {
	if Enabled {
		t.Fatal("Enabled must be false in stub build")
	}
	db, rejections, err := Compile([]Pattern{{ID: 0, Expr: `foo`}})
	if !errors.Is(err, ErrDisabled) {
		t.Fatalf("expected ErrDisabled, got %v", err)
	}
	if db != nil {
		t.Fatal("expected nil DB in stub build")
	}
	if len(rejections) != 1 || rejections[0].Index != 0 || rejections[0].ID != 0 {
		t.Fatalf("expected single rejection at index/id 0, got %v", rejections)
	}
	if rejections[0].Reason == "" {
		t.Error("expected non-empty rejection reason")
	}
}

func TestStubMatchAlwaysDisabled(t *testing.T) {
	var d *DB
	if err := d.Match(nil, nil); !errors.Is(err, ErrDisabled) {
		t.Fatalf("expected ErrDisabled, got %v", err)
	}
}

func TestStubVersion(t *testing.T) {
	if v := Version(); v != "disabled" {
		t.Errorf("expected Version()==\"disabled\" in stub build, got %q", v)
	}
}

func TestStubStatsZero(t *testing.T) {
	var d *DB
	s := d.Stats()
	if s != (Stats{}) {
		t.Errorf("expected zero Stats in stub build, got %+v", s)
	}
}
