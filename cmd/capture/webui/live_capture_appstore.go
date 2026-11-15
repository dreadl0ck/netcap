//go:build appstore

package webui

import (
	"context"
	"fmt"
)

func (s *Server) startLiveHelper(context.Context, []string, string) (func() error, error) {
	return nil, fmt.Errorf("App Store edition cannot launch a capture helper; this API supports in-process file analysis only")
}

func liveCaptureFailure(err error, _ string) string { return err.Error() }
