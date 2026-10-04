// Package db holds the vulnerability and exploit database handles used by
// the stream decoders.
package db

import (
	"fmt"
	"path/filepath"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/internal/vulndb"
)

// Index answers vulnerability and exploit lookups. *vulndb.DB implements it;
// tests substitute their own.
type Index interface {
	Vulnerabilities(vendor, product, version string) ([]vulndb.Vulnerability, error)
	Exploits(vendor, product, version string) ([]vulndb.Exploit, error)
	Close() error
}

var (
	// VulnerabilitiesIndex serves the Vulnerability decoder.
	VulnerabilitiesIndex Index

	// ExploitsIndex serves the Exploit decoder.
	ExploitsIndex Index

	dbLog = zap.NewNop()
)

// SetLogger will set the logger for this package.
func SetLogger(l *zap.Logger) {
	dbLog = l
}

// Path returns the netcap.sqlite path inside the given dbs folder.
func Path(dbsFolder string) string {
	return filepath.Join(dbsFolder, vulndb.FileName)
}

// Open opens the shared vulnerability database read-only.
func Open(path string) (Index, error) {
	dbLog.Info("opening vulnerability db", zap.String("path", path))
	d, err := vulndb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open vulnerability database (run net util -download-dbs): %w", err)
	}
	return d, nil
}

// Close closes index if it is set.
func Close(index Index) {
	if index == nil {
		return
	}
	dbLog.Info("closing vulnerability db")
	if err := index.Close(); err != nil {
		dbLog.Warn("failed to close vulnerability db", zap.Error(err))
	}
}
