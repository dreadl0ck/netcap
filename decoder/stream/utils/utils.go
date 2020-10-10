package utils

import (
	"os"
	"strings"
	"sync"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/defaults"
)

// keep track which paths for content types of extracted files have already been created.
var (
	contentTypeMap   = make(map[string]struct{})
	contentTypeMapMu sync.Mutex
)

// createContentTypePathIfRequired will create the passed in filesystem path once
// it is safe for concurrent access and will block until the path has been created on disk.
func createContentTypePathIfRequired(fsPath string) {
	contentTypeMapMu.Lock()
	if _, ok := contentTypeMap[fsPath]; !ok { // the path has not been created yet
		// add to map
		contentTypeMap[fsPath] = struct{}{}

		// create path
		err := os.MkdirAll(fsPath, defaults.DirectoryPermission)
		if err != nil {
			reassemblyLog.Error(
				"failed to create folder",
				zap.String("path", fsPath),
				zap.Error(err),
			)
		}
	}
	// free lock again
	contentTypeMapMu.Unlock()
}

// trimEncoding removes encoding from a MIME type.
func trimEncoding(ctype string) string {
	parts := strings.Split(ctype, ";")
	if len(parts) > 1 {
		return parts[0]
	}
	return ctype
}
