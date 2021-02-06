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

package logger_test

import (
	"testing"

	"github.com/dreadl0ck/netcap/logger"
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
