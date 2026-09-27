package dbs

import (
	_ "embed"
	"os"
	"path/filepath"
)

//go:embed DATABASE_NOTICES.txt
var databaseNotices []byte

func writeDatabaseNotices(dir string) error {
	return os.WriteFile(filepath.Join(dir, "DATABASE_NOTICES.txt"), databaseNotices, 0o644)
}
