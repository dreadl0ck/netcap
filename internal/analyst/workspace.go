package analyst

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/internal/artifactio"
)

const WorkspaceFile = "analyst-workspace.json"
const WorkspaceLockFile = ".analyst-workspace.lock"

var ErrBusy = errors.New("analyst workspace is leased; stale locks require explicit operator removal")

var storeMu sync.Mutex

type Document struct {
	CatalogueSnapshotSHA256 string            `json:"catalogueSnapshotSHA256,omitempty"`
	IncludedSources         []SourceSelection `json:"includedSources"`
	ID                      string            `json:"id"`
	Revision                int               `json:"revision"`
	Kind                    string            `json:"kind"`
	Title                   string            `json:"title"`
	Body                    string            `json:"body"`
	Binding                 Binding           `json:"binding"`
	Query                   *Query            `json:"query,omitempty"`
	References              []Reference       `json:"references"`
	Review                  string            `json:"review"`
	Reviewer                string            `json:"reviewer,omitempty"`
	UpdatedAt               string            `json:"updatedAt"`
}
type Workspace struct {
	Version   int        `json:"version"`
	Binding   Binding    `json:"binding"`
	Documents []Document `json:"documents"`
}

func LoadWorkspace(ctx context.Context, dir string, binding Binding) (Workspace, error) {
	empty := Workspace{1, binding, []Document{}}
	if err := Check(ctx, dir, binding); err != nil {
		return empty, err
	}
	b, err := artifactio.Read(ctx, dir, WorkspaceFile, 2<<20)
	if errors.Is(err, os.ErrNotExist) {
		return empty, nil
	}
	if err != nil {
		return empty, err
	}
	var w Workspace
	if err = json.Unmarshal(b, &w); err != nil {
		return empty, err
	}
	if w.Version != 1 || w.Binding != binding {
		return empty, ErrStale
	}
	return w, nil
}

// SaveDocument uses revision CAS and an atomic private-file replacement. Reviewed
// content cannot be edited without explicitly returning it to draft.
func SaveDocument(ctx context.Context, dir string, binding Binding, doc Document, expected int) (saved Document, resultErr error) {
	storeMu.Lock()
	defer storeMu.Unlock()
	root, err := openWorkspaceRoot(dir)
	if err != nil {
		return doc, err
	}
	lock, err := root.OpenFile(WorkspaceLockFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		root.Close()
		if os.IsExist(err) {
			return doc, ErrBusy
		}
		return doc, err
	}
	if err = lock.Close(); err != nil {
		_ = root.Remove(WorkspaceLockFile)
		root.Close()
		return doc, err
	}
	defer func() { resultErr = errors.Join(resultErr, root.Remove(WorkspaceLockFile), root.Close()) }()
	if doc.Binding != binding || len(doc.Title) < 1 || len(doc.Title) > 256 || len(doc.Body) > 16384 || len(doc.References) > 16 {
		return doc, fmt.Errorf("invalid document bounds/binding")
	}
	if len(doc.IncludedSources) > 8 {
		return doc, fmt.Errorf("document source inclusion exceeds eight captures")
	}
	if doc.Kind != "query" && doc.Kind != "report" {
		return doc, fmt.Errorf("document kind must be query or report")
	}
	if doc.Review != "draft" && doc.Review != "reviewed" {
		return doc, fmt.Errorf("explicit draft/reviewed state required")
	}
	if doc.Kind == "query" {
		if !IsHash(doc.CatalogueSnapshotSHA256) {
			return doc, fmt.Errorf("saved query requires the complete catalogue snapshot")
		}
		if len(doc.IncludedSources) < 1 || len(doc.IncludedSources) > 8 || doc.IncludedSources[0].Binding != binding {
			return doc, fmt.Errorf("saved query requires its original explicit source inclusion")
		}
		if doc.Query == nil {
			return doc, fmt.Errorf("saved query is required")
		}
		if err := ValidateQuery(*doc.Query); err != nil {
			return doc, err
		}
	}
	if doc.Review == "reviewed" && (doc.Reviewer == "" || len(doc.Reviewer) > 128) {
		return doc, fmt.Errorf("reviewer is required")
	}
	for _, ref := range doc.References {
		if ref.Binding != binding {
			return doc, fmt.Errorf("document references must belong to its capture")
		}
		if _, err := Resolve(ctx, dir, ref); err != nil {
			return doc, err
		}
	}
	w, err := LoadWorkspace(ctx, dir, binding)
	if err != nil {
		return doc, err
	}
	index := -1
	for i, old := range w.Documents {
		if old.ID == doc.ID {
			index = i
		}
	}
	if index < 0 {
		if doc.ID != "" || expected != 0 || len(w.Documents) >= 64 || doc.Review != "draft" {
			return doc, fmt.Errorf("new document requires draft, revision zero and available capacity")
		}
		var id [16]byte
		if _, err = rand.Read(id[:]); err != nil {
			return doc, err
		}
		doc.ID = hex.EncodeToString(id[:])
		doc.Revision = 1
	} else {
		old := w.Documents[index]
		if expected != old.Revision {
			return doc, ErrStale
		}
		if doc.Kind != old.Kind {
			return doc, fmt.Errorf("document kind is immutable")
		}
		if doc.Review == "reviewed" {
			before, after := old, doc
			before.Revision = 0
			after.Revision = 0
			before.Review = ""
			after.Review = ""
			before.Reviewer = ""
			after.Reviewer = ""
			before.UpdatedAt = ""
			after.UpdatedAt = ""
			a, _ := json.Marshal(before)
			b, _ := json.Marshal(after)
			if string(a) != string(b) {
				return doc, fmt.Errorf("save changed content as draft before review")
			}
		}
		doc.Revision = old.Revision + 1
	}
	if doc.Review == "draft" {
		doc.Reviewer = ""
	}
	doc.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if index < 0 {
		w.Documents = append(w.Documents, doc)
	} else {
		w.Documents[index] = doc
	}
	data, err := json.Marshal(w)
	if err != nil {
		return doc, err
	}
	if len(data) > 2<<20 {
		return doc, fmt.Errorf("workspace byte limit exceeded")
	}
	if err = AtomicJSON(ctx, dir, WorkspaceFile, data, func() error { return Check(ctx, dir, binding) }); err != nil {
		return doc, err
	}
	return doc, nil
}

func AtomicJSON(ctx context.Context, dir, name string, data []byte, validate func() error) error {
	if name != filepath.Base(name) || name == "." || name == ".." || strings.ContainsAny(name, "\\\x00") {
		return artifactio.ErrPath
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	root, err := openWorkspaceRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	if old, e := root.Lstat(name); e == nil && (!old.Mode().IsRegular() || old.Mode()&os.ModeSymlink != 0) {
		return artifactio.ErrPath
	} else if e != nil && !os.IsNotExist(e) {
		return e
	}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		return err
	}
	temp := ".analyst-" + hex.EncodeToString(id[:]) + ".tmp"
	f, err := root.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(temp)
	_, writeErr := f.Write(data)
	err = errors.Join(writeErr, f.Sync(), f.Close())
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if validate != nil {
		if err = validate(); err != nil {
			return err
		}
	}
	pinned, err := root.Stat(".")
	if err != nil {
		return err
	}
	current, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(pinned, current) {
		return artifactio.ErrPath
	}
	return root.Rename(temp, name)
}

func openWorkspaceRoot(dir string) (*os.Root, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, artifactio.ErrPath
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	pinned, err := root.Stat(".")
	if err != nil || !os.SameFile(info, pinned) {
		root.Close()
		return nil, artifactio.ErrPath
	}
	return root, nil
}
