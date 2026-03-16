package db

import (
	"fmt"
	"io"
	"time"

	"github.com/blevesearch/bleve"
	"go.uber.org/zap"
)

var (
	// VulnerabilitiesIndex is the handle to the bleve database for vulnerability information
	VulnerabilitiesIndex bleve.Index

	// ExploitsIndex is the handle to the bleve database for exploit information
	ExploitsIndex bleve.Index

	// VulnerabilityDBName is the name of the database directory on disk
	VulnerabilityDBName = "nvd.bleve"
	dbLog               = zap.NewNop()

	// BleveOpenTimeout controls how long to wait for a bleve database to open
	// before returning an error. This prevents indefinite blocking when the
	// underlying BoltDB file is locked by another process (e.g. concurrent test runs).
	BleveOpenTimeout = 10 * time.Second
)

// SetLogger will set the logger for this package.
func SetLogger(l *zap.Logger) {
	dbLog = l
}

// OpenBleve is a wrapper for the bleve open call with a timeout.
// It prevents indefinite blocking when the BoltDB file is locked
// by another process (e.g. when running tests concurrently).
func OpenBleve(path string) (bleve.Index, error) {
	dbLog.Info("opening bleve db", zap.String("path", path))

	type result struct {
		index bleve.Index
		err   error
	}

	ch := make(chan result, 1)

	go func() {
		idx, err := bleve.Open(path)
		ch <- result{idx, err}
	}()

	select {
	case r := <-ch:
		return r.index, r.err
	case <-time.After(BleveOpenTimeout):
		return nil, fmt.Errorf("timeout opening bleve database at %s after %v (database may be locked by another process)", path, BleveOpenTimeout)
	}
}

// CloseBleve is a simple wrapper for the bleve close call
// it's used to log any close operations.
func CloseBleve(index io.Closer) {
	if index == nil {
		return
	}

	dbLog.Info("closing bleve db", zap.String("index", index.(bleve.Index).Name()))

	err := index.Close()
	if err != nil {
		fmt.Println(err)
	}
}
