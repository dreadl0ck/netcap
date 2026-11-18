package file

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
)

var ErrArtifactLimit = errors.New("artifact byte budget exceeded")
var errSharedArtifactBudget = fmt.Errorf("shared extraction capacity: %w", ErrArtifactLimit)
var extractionBudget struct {
	sync.Mutex
	used   int64
	files  int
	active bool
	limit  int64
}

func resetExtractionBudget(active bool) {
	extractionBudget.Lock()
	defer extractionBudget.Unlock()
	extractionBudget.used = 0
	extractionBudget.files = 0
	extractionBudget.active = active
	extractionBudget.limit = GetGlobalConfig().FileExtraction.SizeLimits.MaxInflightBytes
}
func reserveBuffer(n int64) error {
	_, err := reserveBufferRange(n, n)
	return err
}

func reserveBufferRange(minimum, preferred int64) (int64, error) {
	extractionBudget.Lock()
	defer extractionBudget.Unlock()
	if !extractionBudget.active {
		return preferred, nil
	}
	n := min(preferred, extractionBudget.limit-extractionBudget.used)
	if n < minimum {
		return 0, errSharedArtifactBudget
	}
	extractionBudget.used += n
	return n, nil
}
func releaseBuffer(n int64) {
	extractionBudget.Lock()
	defer extractionBudget.Unlock()
	if extractionBudget.active {
		extractionBudget.used -= n
	}
}

// ReadBody retains its allocation reservation until release, including partial reads.
func ReadBody(r io.Reader) ([]byte, func(), error) { return ReadBodyLimit(r, GetMaxFileSize()) }
func ReadBodyLimit(r io.Reader, limit int64) (body []byte, release func(), err error) {
	if r == http.NoBody {
		return nil, func() {}, nil
	}
	if limit <= 0 || limit > 100<<20 {
		limit = 100 << 20
	}
	var reserved int64
	emptyReads := 0
	var once sync.Once
	release = func() { once.Do(func() { releaseBuffer(reserved) }) }
	defer func() {
		if failure := recover(); failure != nil {
			release()
			panic(failure)
		}
	}()
	for {
		var fullErr error
		if int64(len(body)) == limit {
			fullErr = fmt.Errorf("%w: per-file %d", ErrArtifactLimit, limit)
		} else if len(body) == cap(body) {
			preferred := min(limit, max(int64(512), int64(cap(body))*2))
			minimum := preferred
			if len(body) > 0 {
				minimum = int64(len(body)) + 1
			}
			if next, e := reserveBufferRange(minimum, preferred); e != nil {
				if len(body) == 0 {
					return body, release, e
				}
				fullErr = e
			} else {
				grown := make([]byte, len(body), int(next))
				copy(grown, body)
				releaseBuffer(reserved)
				reserved = next
				body = grown
			}
		}
		if fullErr != nil {
			// Readers may report EOF on the next read after filling the buffer.
			var extra [1]byte
			n, e := r.Read(extra[:])
			if n == 0 && e == nil {
				emptyReads++
				if emptyReads >= 100 {
					return body, release, io.ErrNoProgress
				}
				continue
			}
			if n > 0 {
				if e != nil && e != io.EOF {
					return body, release, errors.Join(fullErr, e)
				}
				return body, release, fullErr
			}
			if e == io.EOF {
				e = nil
			}
			return body, release, e
		}
		n, e := r.Read(body[len(body):cap(body)])
		body = body[:len(body)+n]
		if e == io.EOF {
			return body, release, nil
		}
		if e != nil {
			return body, release, e
		}
		if n == 0 {
			emptyReads++
			if emptyReads >= 100 {
				return body, release, io.ErrNoProgress
			}
		} else {
			emptyReads = 0
		}
	}
}

func admitArtifact() error {
	extractionBudget.Lock()
	defer extractionBudget.Unlock()
	if !extractionBudget.active {
		return nil
	}
	maximum := GetGlobalConfig().FileExtraction.SizeLimits.MaxFilesPerSession
	if maximum > 0 && extractionBudget.files >= maximum {
		return fmt.Errorf("artifact count limit exceeded")
	}
	extractionBudget.files++
	return nil
}
