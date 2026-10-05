package dbs

import (
	_ "embed"
	"os"
	"path/filepath"
	"strings"
)

//go:embed DATABASE_NOTICES.txt
var databaseNotices []byte

// User-installed data and the retired Alexa feed must never be republished.
func excludedFromDistribution(name string) bool {
	name = filepath.Base(name)
	return name == "nmap-service-probes" || name == "domain-whitelist.csv" ||
		(strings.HasPrefix(name, "GeoLite2-") && strings.HasSuffix(name, ".mmdb"))
}

func writeDatabaseNotices(dir string) error {
	return os.WriteFile(filepath.Join(dir, "DATABASE_NOTICES.txt"), databaseNotices, 0o644)
}
