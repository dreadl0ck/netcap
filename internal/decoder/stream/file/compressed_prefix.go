package file

import (
	"compress/gzip"
	"errors"
	"io"
)

// The wire artifact remains authoritative. A bounded decoded prefix is a
// separate, explicitly incomplete child when only integrity/trailer data fails.
func recoverGzipPrefix(body []byte, limit int64) ([]byte, func(), error) {
	decoded, release, err := decodeByteLayer(body, "gzip", limit)
	if len(decoded) > 0 && (errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, gzip.ErrChecksum)) {
		return decoded, release, err
	}
	if release != nil {
		release()
	}
	return nil, nil, err
}
