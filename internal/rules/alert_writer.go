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

package rules

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
)

// AlertWriter is an interface for writing alerts.
type AlertWriter interface {
	WriteAlert(alert *types.Alert) error
	Close() error
}

// FileAlertWriter appends complete gzip members, readable before Close.
type FileAlertWriter struct {
	mu       sync.Mutex
	store    *alertStore
	closed   bool
	closeErr error
}

const maxAlertRecordSize = 16 << 20

type alertFile interface {
	Write([]byte) (int, error)
	Sync() error
	Truncate(int64) error
	Close() error
}

type alertStore struct {
	mu     sync.Mutex
	path   string
	file   alertFile
	size   int64
	refs   int
	err    error
	buffer bytes.Buffer
	gzip   *gzip.Writer
}

// Rule jobs in one process share a file; separate processes must use separate output directories.
var alertStores = struct {
	sync.Mutex
	files map[string]*alertStore
}{files: make(map[string]*alertStore)}

// NewFileAlertWriter validates existing history without retaining it in memory.
// A new file is created only on the first alert.
func NewFileAlertWriter(outputDir string) (*FileAlertWriter, error) {
	if outputDir == "" {
		outputDir = "."
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, err
	}
	dir, err := filepath.Abs(outputDir)
	if err != nil {
		return nil, err
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "Alert.ncap.gz")
	alertStores.Lock()
	defer alertStores.Unlock()
	store := alertStores.files[path]
	if store == nil {
		store = &alertStore{path: path}
		file, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0600)
		if err == nil {
			if err = validateAlertFile(file); err != nil {
				return nil, errors.Join(fmt.Errorf("invalid alert history: %w", err), file.Close())
			}
			info, err := file.Stat()
			if err != nil {
				return nil, errors.Join(err, file.Close())
			}
			store.file, store.size = file, info.Size()
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		alertStores.files[path] = store
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.err != nil {
		return nil, store.err
	}
	store.refs++
	return &FileAlertWriter{store: store}, nil
}

func validateAlertFile(file *os.File) error {
	gz, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gz.Close()
	reader := bufio.NewReader(gz)
	var buffer []byte
	for index := 0; ; index++ {
		size, err := binary.ReadUvarint(reader)
		if err == io.EOF && index > 0 {
			return nil
		}
		if err != nil {
			return err
		}
		if size > maxAlertRecordSize {
			return fmt.Errorf("alert record exceeds %d bytes", maxAlertRecordSize)
		}
		if cap(buffer) < int(size) {
			buffer = make([]byte, size)
		}
		buffer = buffer[:size]
		if _, err := io.ReadFull(reader, buffer); err != nil {
			return err
		}
		if index == 0 {
			var header types.Header
			if err := proto.Unmarshal(buffer, &header); err != nil {
				return err
			}
			if header.Type != types.Type_NC_Alert {
				return fmt.Errorf("expected Alert header, got %s", header.Type)
			}
		} else {
			var alert types.Alert
			if err := proto.Unmarshal(buffer, &alert); err != nil {
				return err
			}
		}
	}
}

// WriteAlert returns only after the complete alert member is synced to disk.
func (w *FileAlertWriter) WriteAlert(alert *types.Alert) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return os.ErrClosed
	}
	if alert == nil {
		return errors.New("alert cannot be nil")
	}
	if alert.Size() > maxAlertRecordSize {
		return fmt.Errorf("alert record exceeds %d bytes", maxAlertRecordSize)
	}
	s := w.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	if s.file == nil {
		file, err := os.OpenFile(s.path, os.O_CREATE|os.O_EXCL|os.O_RDWR|os.O_APPEND, 0600)
		if err != nil {
			s.err = err
			return err
		}
		s.file = file
	}
	if s.size == 0 {
		if err := s.appendMember(netio.NewHeader(types.Type_NC_Alert, "", "", false, time.Now())); err != nil {
			return err
		}
		if err := syncAlertDirectory(filepath.Dir(s.path)); err != nil {
			s.err = err
			return err
		}
	}
	return s.appendMember(alert)
}

func syncAlertDirectory(path string) error {
	// Windows cannot sync directory handles; the file itself is always synced.
	if runtime.GOOS == "windows" {
		return nil
	}
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func (s *alertStore) appendMember(msg proto.Message) error {
	s.buffer.Reset()
	if s.gzip == nil {
		var err error
		s.gzip, err = gzip.NewWriterLevel(&s.buffer, defaults.CompressionLevel)
		if err != nil {
			return err
		}
	} else {
		s.gzip.Reset(&s.buffer)
	}
	if err := delimited.NewWriter(s.gzip).PutProto(msg); err != nil {
		return errors.Join(err, s.gzip.Close())
	}
	if err := s.gzip.Close(); err != nil {
		return err
	}
	n, err := s.file.Write(s.buffer.Bytes())
	if err == nil && n != s.buffer.Len() {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = s.file.Sync()
	}
	if err != nil {
		// Preserve the last committed member on a partial write or sync failure.
		s.err = errors.Join(err, s.file.Truncate(s.size), s.file.Sync())
		return s.err
	}
	s.size += int64(n)
	return nil
}

// Close releases this writer; it is idempotent and reports persistence failures.
func (w *FileAlertWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return w.closeErr
	}
	w.closed = true
	alertStores.Lock()
	defer alertStores.Unlock()
	s := w.store
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refs--
	w.closeErr = s.err
	if s.refs == 0 {
		delete(alertStores.files, s.path)
		if s.file != nil {
			w.closeErr = errors.Join(w.closeErr, s.file.Close())
		}
	}
	return w.closeErr
}
