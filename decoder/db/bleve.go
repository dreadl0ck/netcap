package db

import (
	"fmt"
	"io"

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
)

// SetLogger will set the logger for this package.
func SetLogger(l *zap.Logger) {
	dbLog = l
}

// OpenBleve is a simple wrapper for the bleve open call
// it's used to log any open operations.
func OpenBleve(path string) (bleve.Index, error) {
	dbLog.Info("opening bleve db", zap.String("path", path))

	return bleve.Open(path)
}

// CloseBleve is a simple wrapper for the bleve close call
// it's used to log any close operations.
func CloseBleve(index io.Closer) {
	if index == nil {
		return
	}

	dbLog.Info("closing bleve db", zap.String("index", fmt.Sprint(index)))

	err := index.Close()
	if err != nil {
		fmt.Println(err)
	}
}
