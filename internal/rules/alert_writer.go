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
	"context"
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
	header *types.Header
}

// Rule jobs in one process share a file; separate processes must use separate output directories.
type alertStoreSlot struct {
	gate  chan struct{}
	store *alertStore
	users int // guarded by alertStores
}

var alertStores = struct {
	sync.Mutex
	paths map[string]*alertStoreSlot
}{paths: make(map[string]*alertStoreSlot)}

func lockAlertStore(path string) (*alertStoreSlot, func()) {
	slot, unlock, _ := lockAlertStoreContext(context.Background(), path)
	return slot, unlock
}

func lockAlertStoreContext(ctx context.Context, path string) (*alertStoreSlot, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	alertStores.Lock()
	slot := alertStores.paths[path]
	if slot == nil {
		slot = &alertStoreSlot{gate: make(chan struct{}, 1)}
		alertStores.paths[path] = slot
	}
	slot.users++
	alertStores.Unlock()
	release := func() {
		alertStores.Lock()
		slot.users--
		// A holder and every waiter count as users, so zero permits reading store.
		if slot.users == 0 && slot.store == nil {
			delete(alertStores.paths, path)
		}
		alertStores.Unlock()
	}
	select {
	case slot.gate <- struct{}{}:
	case <-ctx.Done():
		release()
		return nil, nil, ctx.Err()
	}
	unlock := func() { <-slot.gate; release() }
	if err := ctx.Err(); err != nil {
		unlock()
		return nil, nil, err
	}
	return slot, unlock, nil
}

// NewFileAlertWriter validates existing history without retaining it in memory.
// A new file is created only on the first alert.
func NewFileAlertWriter(outputDir string) (*FileAlertWriter, error) {
	return NewFileAlertWriterContext(context.Background(), outputDir)
}

// NewFileAlertWriterContext allows cancellation of the setup wait and history validation.
func NewFileAlertWriterContext(ctx context.Context, outputDir string) (*FileAlertWriter, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return newFileAlertWriter(ctx, outputDir, func(file *os.File) error {
		return validateAlertHistory(ctx, file)
	})
}

func newFileAlertWriter(ctx context.Context, outputDir string, validate func(*os.File) error) (*FileAlertWriter, error) {
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
	slot, unlock, err := lockAlertStoreContext(ctx, path)
	if err != nil {
		return nil, err
	}
	defer unlock()
	store := slot.store
	if store == nil {
		store = &alertStore{path: path}
		file, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0600)
		if err == nil {
			if err = validate(file); err != nil {
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
		slot.store = store
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := ctx.Err(); err != nil {
		if store.refs == 0 {
			slot.store = nil
			if store.file != nil {
				err = errors.Join(err, store.file.Close())
			}
		}
		return nil, err
	}
	if store.err != nil {
		return nil, store.err
	}
	store.refs++
	return &FileAlertWriter{store: store}, nil
}

func validateAlertFile(file *os.File) error {
	return validateAlertHistory(context.Background(), file)
}

type alertHistoryReader struct {
	ctx   context.Context
	input io.Reader
}

func (r alertHistoryReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.input.Read(p[:min(len(p), 64<<10)])
}

func validateAlertHistory(ctx context.Context, input io.Reader) error {
	gz, err := gzip.NewReader(alertHistoryReader{ctx, input})
	if err != nil {
		return err
	}
	defer gz.Close()
	reader := bufio.NewReader(alertHistoryReader{ctx, gz})
	var buffer []byte
	for index := 0; ; index++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		size, err := binary.ReadUvarint(reader)
		if err == io.EOF && index > 0 {
			return ctx.Err()
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
		header := s.header
		if header == nil {
			header = netio.NewHeader(types.Type_NC_Alert, "", "", false, time.Now())
		}
		if err := s.appendMember(header); err != nil {
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

// Error includes failures raised by other writers sharing this file.
func (w *FileAlertWriter) Error() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.store.mu.Lock()
	defer w.store.mu.Unlock()
	return w.store.err
}

// Close releases this writer; it is idempotent and reports persistence failures.
func (w *FileAlertWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return w.closeErr
	}
	w.closed = true
	s := w.store
	slot, unlock := lockAlertStore(s.path)
	defer unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refs--
	w.closeErr = s.err
	if s.refs == 0 {
		slot.store = nil
		if s.file != nil {
			w.closeErr = errors.Join(w.closeErr, s.file.Close())
		}
	}
	return w.closeErr
}
