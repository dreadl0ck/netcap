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

package distributed

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
)

// readRecords reads an output file with netcap's normal reader and returns
// its header and record count.
func readRecords(t testing.TB, path string) (*types.Header, int) {
	t.Helper()

	r, err := netio.Open(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	hdr, err := r.ReadHeader()
	if err != nil {
		t.Fatalf("%s: header: %v", path, err)
	}

	rec := netio.InitRecord(hdr.Type)
	n := 0
	for {
		err = r.Next(rec)
		if errors.Is(err, io.EOF) {
			return hdr, n
		}
		if err != nil {
			t.Fatalf("%s: record %d: %v", path, n, err)
		}
		n++
	}
}

func TestSinkRefusesUnsafeClientNames(t *testing.T) {
	s, err := NewSink(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	b := &types.Batch{MessageType: types.Type_NC_TCP, Data: delimitedTCP(t, 1)}
	for _, name := range []string{"", ".", "..", "../x", "/etc", "a/b", "a\\b", "x\x00"} {
		if err = s.Write(name, &types.AgentHello{}, b, 1); err == nil {
			t.Errorf("client name %q accepted", name)
		}
	}

	entries, _ := os.ReadDir(s.Root())
	if len(entries) != 0 {
		t.Fatalf("unsafe names created %d entries", len(entries))
	}
	if _, err = os.Stat(filepath.Join(filepath.Dir(s.Root()), "x")); err == nil {
		t.Fatal("wrote outside the output directory")
	}
}

// v0.9.15 dropped the first batch per file and raced on its file map.
func TestSinkConcurrentWritesKeepEveryBatch(t *testing.T) {
	s, err := NewSink(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	const writers, perBatch = 50, 3

	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := &types.Batch{MessageType: types.Type_NC_TCP, Data: delimitedTCP(t, perBatch)}
			if errW := s.Write("sensor", &types.AgentHello{Source: "eth0"}, b, perBatch); errW != nil {
				t.Error(errW)
			}
		}()
	}
	wg.Wait()

	infos, err := s.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 || infos[0].Records != writers*perBatch {
		t.Fatalf("infos %+v", infos)
	}

	hdr, n := readRecords(t, infos[0].Path)
	if n != writers*perBatch {
		t.Fatalf("read %d records, want %d", n, writers*perBatch)
	}
	if hdr.Type != types.Type_NC_TCP || hdr.InputSource != "eth0" {
		t.Fatalf("header %+v", hdr)
	}

	if st, _ := os.Stat(infos[0].Path); st.Mode().Perm() != sinkFilePerm {
		t.Errorf("file mode %o", st.Mode().Perm())
	}

	if err = s.Write("sensor", &types.AgentHello{}, &types.Batch{MessageType: types.Type_NC_TCP}, 0); !errors.Is(err, ErrSinkClosed) {
		t.Fatalf("write after close: %v", err)
	}
}

func TestSinkNeverTruncatesEarlierRuns(t *testing.T) {
	root := t.TempDir()

	for run := 0; run < 2; run++ {
		s, err := NewSink(root)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.Write("sensor", &types.AgentHello{}, &types.Batch{MessageType: types.Type_NC_TCP, Data: delimitedTCP(t, 2)}, 2); err != nil {
			t.Fatal(err)
		}
		if _, err = s.Close(); err != nil {
			t.Fatal(err)
		}
	}

	for _, name := range []string{"TCP.ncap.gz", "TCP-1.ncap.gz"} {
		if _, n := readRecords(t, filepath.Join(root, "sensor", name)); n != 2 {
			t.Fatalf("%s: %d records", name, n)
		}
	}
}
