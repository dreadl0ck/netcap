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

package io

import (
	"os"
	"testing"

	"github.com/dreadl0ck/netcap/defaults"
)

func TestDumpCSV(t *testing.T) {
	f, err := os.Create("../tests/testdump.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		errClose := f.Close()
		if errClose != nil {
			t.Fatal("failed to close file:", errClose)
		}
	}()

	err = Dump(f, DumpConfig{
		Path:      "../tests/testdata/TCP.ncap.gz",
		Separator: ",",
		UTC:       false,
		CSV:       true,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDumpJSON(t *testing.T) {
	f, err := os.Create("../tests/testdump.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		errClose := f.Close()
		if errClose != nil {
			t.Fatal("failed to close file:", errClose)
		}
	}()

	err = Dump(f, DumpConfig{
		Path: "../tests/testdata/TCP.ncap.gz",
		JSON: true,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDumpStruc(t *testing.T) {
	f, err := os.Create("../tests/testdump.log")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		errClose := f.Close()
		if errClose != nil {
			t.Fatal("failed to close file:", errClose)
		}
	}()

	err = Dump(f, DumpConfig{
		Path:       "../tests/testdata/TCP.ncap.gz",
		Structured: true,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCloseFile(t *testing.T) {
	f := createFile("../tests/TCP", defaults.FileExtensionCompressed)
	if f == nil {
		t.Fatal("nil file handle received")
	}

	n, s := closeFile("tests", f, "TCP", 0)
	if n != "TCP.ncap.gz" {
		t.Fatal(n, " != TCP.ncap.gz")
	}

	if s != 0 {
		t.Fatal("expected length of 0 bytes")
	}
}

func TestCreateFile(t *testing.T) {
	f := createFile("../tests/CreateFileTCP", defaults.FileExtensionCompressed)
	if f == nil {
		t.Fatal("nil file handle received")
	}

	err := f.Close()
	if err != nil {
		t.Fatal(err)
	}
}
