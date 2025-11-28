/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package logger_test

import (
	"testing"

	"github.com/dreadl0ck/netcap/internal/logger"
)

func TestInitZapLogger(t *testing.T) {
	l, f, err := logger.InitZapLogger("doesnotexist", "testlog", false)
	if err == nil {
		t.Fatal("expected an error because the outpath does not exist")
	}
	if l != nil {
		t.Fatal("expected nil logger")
	}
	if f != nil {
		t.Fatal("expected nil log file handle")
	}

	l, f, err = logger.InitZapLogger("../tests", "testlog", false)
	if err != nil {
		t.Fatal("expected no error because the outpath exists")
	}
	if l == nil {
		t.Fatal("expected a logger")
	}
	if f == nil {
		t.Fatal("expected log file handle")
	}

	l.Info("test")

	err = f.Close()
	if err != nil {
		t.Fatal("expected no error")
	}
}

func TestInitDebugLogger(t *testing.T) {
	// debug mode inactive: should succeed and return a discarding logger and nil file handle
	l, f, err := logger.InitDebugLogger("doesnotexist", "testlog", false)
	if err != nil {
		t.Fatal("expected no error")
	}
	if l == nil {
		t.Fatal("expected a logger")
	}
	if f != nil {
		t.Fatal("expected nil log file handle")
	}

	// debug mode active: should fail because outpath does not exist
	l, f, err = logger.InitDebugLogger("doesnotexist", "testlog", true)
	if err == nil {
		t.Fatal("expected an error because the outpath does not exist")
	}
	if l != nil {
		t.Fatal("expected nil logger")
	}
	if f != nil {
		t.Fatal("expected nil log file handle")
	}

	l, f, err = logger.InitDebugLogger("../tests", "testlog", true)
	if err != nil {
		t.Fatal("expected no error because the outpath exists")
	}
	if l == nil {
		t.Fatal("expected a logger")
	}
	if f == nil {
		t.Fatal("expected log file handle")
	}

	l.Println("test")

	err = f.Close()
	if err != nil {
		t.Fatal("expected no error")
	}
}
