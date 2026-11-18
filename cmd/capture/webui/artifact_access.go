package webui

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/dreadl0ck/netcap/internal/artifactio"
)

var errArtifactListingLimit = errors.New("artifact listing limit exceeded")

func walkArtifactListing(ctx context.Context, dir string, remaining int, visit func(string, os.FileInfo) error) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return artifactio.ErrPath
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	if pinned, err := root.Stat("."); err != nil || !os.SameFile(info, pinned) {
		return artifactio.ErrPath
	}
	var walk func(*os.Root, string, int) error
	walk = func(directory *os.Root, name string, depth int) error {
		if depth > 32 {
			return errArtifactListingLimit
		}
		names, err := func() ([]string, error) {
			f, err := directory.Open(".")
			if err != nil {
				return nil, err
			}
			defer f.Close()
			var names []string
			for {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				batch, err := f.Readdirnames(min(256, remaining+1))
				remaining -= len(batch)
				if remaining < 0 {
					return nil, errArtifactListingLimit
				}
				names = append(names, batch...)
				if err == io.EOF {
					return names, nil
				}
				if err != nil {
					return nil, err
				}
			}
		}()
		if err != nil {
			return err
		}
		slices.Sort(names)
		for _, child := range names {
			if err := ctx.Err(); err != nil {
				return err
			}
			path := filepath.Join(name, child)
			info, err := directory.Lstat(child)
			if err != nil {
				return err
			}
			switch {
			case info.IsDir():
				sub, err := directory.OpenRoot(child)
				if err != nil {
					return err
				}
				pinned, err := sub.Stat(".")
				if err != nil || !os.SameFile(info, pinned) {
					sub.Close()
					return artifactio.ErrPath
				}
				err = walk(sub, path, depth+1)
				sub.Close()
				if err != nil {
					return err
				}
			case !info.Mode().IsRegular():
				return artifactio.ErrPath
			case !strings.HasPrefix(child, ".netcap-artifact-"):
				err = visit(path, info)
			}
			if err != nil {
				return err
			}
		}
		return nil
	}
	return walk(root, ".", 0)
}

func (s *Server) artifactDirectory(w http.ResponseWriter, r *http.Request) (string, bool) {
	selected, ok := s.selectedCapture(w, r)
	if !ok {
		return "", false
	}
	return filepath.Join(selected.OutputDir, "files"), true
}
func artifactAccessError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, os.ErrNotExist):
		http.Error(w, "Artifact not found", 404)
	case errors.Is(err, artifactio.ErrPath), errors.Is(err, os.ErrPermission):
		http.Error(w, "Invalid artifact path", 403)
	default:
		http.Error(w, "Artifact access failed", 500)
	}
}
