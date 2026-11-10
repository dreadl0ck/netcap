package file

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
)

var ErrArtifactLimit = errors.New("artifact byte budget exceeded")
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
	extractionBudget.Lock()
	defer extractionBudget.Unlock()
	if !extractionBudget.active {
		return nil
	}
	if n > extractionBudget.limit-extractionBudget.used {
		return ErrArtifactLimit
	}
	extractionBudget.used += n
	return nil
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
	for {
		if int64(len(body)) == limit {
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
				return body, release, fmt.Errorf("%w: per-file %d", ErrArtifactLimit, limit)
			}
			if e == io.EOF {
				e = nil
			}
			return body, release, e
		}
		if len(body) == cap(body) {
			next := min(limit, max(int64(512), int64(cap(body))*2))
			if e := reserveBuffer(next); e != nil {
				return body, release, e
			}
			grown := make([]byte, len(body), int(next))
			copy(grown, body)
			releaseBuffer(reserved)
			reserved = next
			body = grown
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
