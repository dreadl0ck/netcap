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
	"compress/gzip"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
)

const (
	sinkDirPerm  = 0o750
	sinkFilePerm = 0o640
)

// ErrSinkClosed is returned by Write after Close.
var ErrSinkClosed = errors.New("sink closed")

// Sink writes batches into <root>/<client>/<Type>.ncap.gz, one gzip stream per
// client and type. It is safe for concurrent use.
type Sink struct {
	root string

	mu     sync.Mutex
	files  map[sinkKey]*sinkFile
	closed bool
}

type sinkKey struct {
	client string
	typ    types.Type
}

type sinkFile struct {
	mu      sync.Mutex
	path    string
	f       *os.File
	gw      *gzip.Writer
	records int64
}

// NewSink creates root if needed and returns a sink writing below it.
func NewSink(root string) (*Sink, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(abs, sinkDirPerm); err != nil {
		return nil, err
	}

	return &Sink{root: abs, files: map[sinkKey]*sinkFile{}}, nil
}

// Root returns the absolute output directory.
func (s *Sink) Root() string { return s.root }

// clientDir maps a client name to its directory, refusing anything that is not
// a single path segment directly below root. Names come from the allowlist and
// are validated there; this is the second guard.
func (s *Sink) clientDir(client string) (string, error) {
	if !ValidName(client) {
		return "", fmt.Errorf("invalid client name %q", client)
	}

	dir := filepath.Join(s.root, client)

	rel, err := filepath.Rel(s.root, dir)
	if err != nil || rel != client || strings.ContainsRune(rel, filepath.Separator) {
		return "", fmt.Errorf("client name %q escapes the output directory", client)
	}

	return dir, nil
}

// Write appends the records of b, which must already have been validated with
// CountRecords, to the file for (client, b.MessageType). The file and its
// header are created on first use, and the first batch is written like any
// other. numRecords is added to the file's record count.
func (s *Sink) Write(client string, hello *types.AgentHello, b *types.Batch, numRecords int) error {
	sf, err := s.file(client, hello, b.MessageType)
	if err != nil {
		return err
	}

	sf.mu.Lock()
	defer sf.mu.Unlock()

	if sf.gw == nil {
		return ErrSinkClosed
	}
	if _, err = sf.gw.Write(b.Data); err != nil {
		return err
	}
	// Sync-flush so acknowledged data has left process memory.
	if err = sf.gw.Flush(); err != nil {
		return err
	}
	sf.records += int64(numRecords)

	return nil
}

func (s *Sink) file(client string, hello *types.AgentHello, t types.Type) (*sinkFile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, ErrSinkClosed
	}

	key := sinkKey{client: client, typ: t}
	if sf, ok := s.files[key]; ok {
		return sf, nil
	}

	dir, err := s.clientDir(client)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(dir, sinkDirPerm); err != nil {
		return nil, err
	}

	name := strings.TrimPrefix(t.String(), defaults.NetcapTypePrefix)
	if !ValidName(name) {
		return nil, fmt.Errorf("invalid record type %d", t)
	}

	f, path, err := createExclusive(dir, name)
	if err != nil {
		return nil, err
	}

	gw := gzip.NewWriter(f)
	hdr := netio.NewHeader(t, hello.GetSource(), hello.GetVersion(), hello.GetContainsPayloads(), time.Now())
	if err = delimited.NewWriter(gw).PutProto(hdr); err != nil {
		_ = f.Close()
		_ = os.Remove(path)

		return nil, err
	}

	sf := &sinkFile{path: path, f: f, gw: gw}
	s.files[key] = sf

	return sf, nil
}

// createExclusive creates dir/name.ncap.gz, or name-1, name-2, ... if a file
// from an earlier run exists. Existing files are never truncated.
func createExclusive(dir, name string) (*os.File, string, error) {
	for i := 0; i < 10000; i++ {
		base := name
		if i > 0 {
			base += "-" + strconv.Itoa(i)
		}

		path := filepath.Join(dir, base+defaults.FileExtensionCompressed)

		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, sinkFilePerm)
		if err == nil {
			return f, path, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, "", err
		}
	}

	return nil, "", fmt.Errorf("no free file name for %s in %s", name, dir)
}

// SinkFileInfo describes one output file.
type SinkFileInfo struct {
	Client  string
	Type    types.Type
	Path    string
	Records int64
}

// Close finalizes every gzip stream and closes the files. Further writes fail.
func (s *Sink) Close() ([]SinkFileInfo, error) {
	s.mu.Lock()
	s.closed = true
	files := s.files
	s.files = map[sinkKey]*sinkFile{}
	s.mu.Unlock()

	var (
		infos []SinkFileInfo
		errs  []error
	)

	for key, sf := range files {
		sf.mu.Lock()
		if sf.gw != nil {
			errs = append(errs, sf.gw.Close(), sf.f.Sync(), sf.f.Close())
			sf.gw = nil
		}
		infos = append(infos, SinkFileInfo{Client: key.client, Type: key.typ, Path: sf.path, Records: sf.records})
		sf.mu.Unlock()
	}

	return infos, errors.Join(errs...)
}
