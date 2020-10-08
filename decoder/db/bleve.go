package db

import (
	"fmt"
	"io"

	"github.com/blevesearch/bleve"
	"go.uber.org/zap"
)

var (
	VulnerabilitiesIndex bleve.Index
	ExploitsIndex        bleve.Index

	VulnDBName = "nvd.bleve"
	dbLog      *zap.Logger
)

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
