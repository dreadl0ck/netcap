package file

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
)

// The wire artifact remains authoritative. A bounded decoded prefix is a
// separate, explicitly incomplete child when only integrity/trailer data fails.
func recoverGzipPrefix(body []byte, limit int64) ([]byte, func(), error) {
	r, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	decoded, release, err := ReadBodyLimit(r, limit)
	_ = r.Close()
	if len(decoded) > 0 && (errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, gzip.ErrChecksum)) {
		return decoded, release, err
	}
	release()
	return nil, nil, err
}
