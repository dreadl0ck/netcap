/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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
