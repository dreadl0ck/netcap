package webui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func admitSchemaSearchPath(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("schema path must be absolute")
	}
	path = filepath.Clean(path)
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("schema path is unavailable")
	}
	if strings.EqualFold(resolved, filepath.VolumeName(resolved)+string(filepath.Separator)) {
		return "", fmt.Errorf("choose a dedicated schema directory or regular .proto file")
	}
	home, _ := os.UserHomeDir()
	for _, root := range []string{string(filepath.Separator), "/etc", "/private/etc", "/proc", "/sys", "/dev", "/System", "/Windows", "/Users", "/home", "/private", "/var", "/usr", "/opt", home, os.Getenv("SystemRoot")} {
		if root == "" {
			continue
		}
		if strings.EqualFold(filepath.Clean(resolved), filepath.Clean(root)) {
			return "", fmt.Errorf("choose a dedicated schema directory or regular .proto file")
		}
	}
	for _, root := range []string{"/etc", "/private/etc", "/proc", "/sys", "/dev", "/System", os.Getenv("SystemRoot")} {
		if root != "" && strings.HasPrefix(strings.ToLower(resolved), strings.ToLower(filepath.Clean(root)+string(filepath.Separator))) {
			return "", fmt.Errorf("system directories are not schema sources")
		}
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && (!info.Mode().IsRegular() || !strings.HasSuffix(path, ".proto"))) {
		return "", fmt.Errorf("schema source must be a dedicated directory or regular .proto file")
	}
	snapshot, err := snapshotSchemaSources(&jobSettings{SchemaPaths: []string{path}})
	if err != nil {
		return "", fmt.Errorf("schema source cannot be snapshotted within 256 files (2 MiB each), 16 MiB total, 10000 entries and 16 levels")
	}
	snapshot.cleanup()
	return path, nil
}
