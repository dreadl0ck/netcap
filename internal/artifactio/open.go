package artifactio

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
)

var ErrPath = errors.New("invalid artifact path")

// Open confines descriptor access to the selected root and rejects stored symlinks.
func Open(directory, name string) (*os.File, os.FileInfo, error) {
	if strings.HasPrefix(filepath.Base(name), ".netcap-artifact-") {
		return nil, nil, ErrPath
	}
	if name == "" || !filepath.IsLocal(name) || strings.ContainsAny(name, "\\\x00") {
		return nil, nil, ErrPath
	}
	parts := strings.Split(filepath.ToSlash(name), "/")
	for _, p := range parts {
		if p == ".." || p == "." || p == "" {
			return nil, nil, ErrPath
		}
	}
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
	var before os.FileInfo
	for i := range parts {
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
	f, info, err := Open(directory, name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if limit <= 0 || info.Size() > limit {
		return nil, fmt.Errorf("artifact exceeds %d byte limit", limit)
	}
	readLimit := limit
	if readLimit < math.MaxInt64 {
		readLimit++
	}
	b, err := io.ReadAll(io.LimitReader(&contextReader{ctx, f}, readLimit))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("artifact exceeds %d byte limit", limit)
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
