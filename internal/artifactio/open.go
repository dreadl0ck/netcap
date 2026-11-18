package artifactio

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var ErrPath = errors.New("invalid artifact path")

// Open confines descriptor access to the selected root and rejects stored symlinks.
func Open(directory, name string) (*os.File, os.FileInfo, error) {
	rootInfo, err := os.Lstat(directory)
	if err != nil {
		return nil, nil, err
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, nil, ErrPath
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, nil, err
	}
	defer root.Close()
	pinned, err := root.Stat(".")
	if err != nil || !os.SameFile(rootInfo, pinned) {
		return nil, nil, ErrPath
	}
	return OpenInRoot(root, name)
}

// OpenInRoot opens a regular artifact relative to an already pinned root.
func OpenInRoot(root *os.Root, name string) (*os.File, os.FileInfo, error) {
	if name == "" || !filepath.IsLocal(name) || strings.ContainsAny(name, "\\\x00") || strings.HasPrefix(filepath.Base(name), ".netcap-artifact-") {
		return nil, nil, ErrPath
	}
	parts := strings.Split(filepath.ToSlash(name), "/")
	var before os.FileInfo
	for i := range parts {
		if parts[i] == ".." || parts[i] == "." || parts[i] == "" {
			return nil, nil, ErrPath
		}
		var err error
		before, err = root.Lstat(filepath.Join(parts[:i+1]...))
		if err != nil {
			return nil, nil, err
		}
		if before.Mode()&os.ModeSymlink != 0 || (i < len(parts)-1 && !before.IsDir()) {
			return nil, nil, ErrPath
		}
	}
	if !before.Mode().IsRegular() {
		return nil, nil, ErrPath
	}
	f, err := openRegular(root, name)
	if err != nil {
		return nil, nil, err
	}
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		f.Close()
		return nil, nil, ErrPath
	}
	return f, after, nil
}

func Read(ctx context.Context, directory, name string, limit int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, info, err := Open(directory, name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if limit <= 0 || info.Size() > limit || info.Size() > int64(int(^uint(0)>>1)) {
		return nil, fmt.Errorf("artifact exceeds %d byte limit", limit)
	}
	b := make([]byte, int(info.Size()))
	r := &contextReader{ctx, f}
	for offset := 0; offset < len(b); {
		end := offset + min(64<<10, len(b)-offset)
		if _, err := io.ReadFull(r, b[offset:end]); err != nil {
			return nil, err
		}
		offset = end
	}
	var extra [1]byte
	if n, err := io.ReadFull(r, extra[:]); n != 0 {
		return nil, fmt.Errorf("artifact changed during read")
	} else if err != io.EOF {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
		return nil, fmt.Errorf("artifact changed during read")
	}
	return b, nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(b)
}
