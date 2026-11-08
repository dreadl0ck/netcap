package waf

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/dreadl0ck/netcap/internal/firewalltransport"
	"github.com/dreadl0ck/netcap/internal/policy"
)

// NativeBodyBytes reserves space for every bounded HTTP metadata field.
const NativeBodyBytes = policy.MaxEventBytes - 5*maxInspectionFieldBytes - maxInspectionHeaderBytes - 1024
const bodyMemoryBytes = 64 << 10

type BodyCapabilities struct {
	MaxRequestBytes           int64
	MaxResponseBytes          int64
	MaxNativeBodyBytes        int
	MemorySpoolBytes          int
	RequestRequiresBody       bool
	ResponseRequiresBody      bool
	MaxStructuredBytes        int
	CorazaResponseMemoryBytes int64
	EffectiveRequestBytes     int64
	EffectiveResponseBytes    int64
	MaxBufferedBytes          int64
	BufferedBytes             int64
	InspectResponseBody       bool
}

// JSON, XML and URL-encoded parsers additionally bound scalar allocations.
func (f *Firewall) BodyCapabilities() BodyCapabilities {
	p := f.Policy()
	c := BodyCapabilities{MaxRequestBytes: f.cfg.MaxBodyBytes, MaxResponseBytes: f.cfg.MaxResponseBytes, MaxNativeBodyBytes: NativeBodyBytes, MemorySpoolBytes: bodyMemoryBytes, RequestRequiresBody: policyRequiresBody(p, "request"), ResponseRequiresBody: policyRequiresBody(p, "response"), MaxStructuredBytes: NativeBodyBytes}
	c.MaxBufferedBytes = f.buffers.Limit()
	c.BufferedBytes = f.buffers.Used()
	c.InspectResponseBody = f.cfg.InspectResponse
	c.EffectiveRequestBytes = c.MaxRequestBytes
	c.EffectiveResponseBytes = c.MaxResponseBytes
	if c.RequestRequiresBody {
		c.EffectiveRequestBytes = min(c.MaxRequestBytes, NativeBodyBytes)
	}
	if c.ResponseRequiresBody {
		c.EffectiveResponseBytes = min(c.MaxResponseBytes, NativeBodyBytes)
	}
	if f.cfg.CorazaCRS && f.cfg.InspectResponse {
		c.CorazaResponseMemoryBytes = f.cfg.MaxResponseBytes + 1
	}
	return c
}

// bodyStore owns one representation; independent SectionReaders share its file.
// The handler and transport views each release one reference.
type bodyStore struct {
	mu      sync.Mutex
	refs    int
	data    []byte
	file    *os.File
	size    int64
	budget  *firewalltransport.BufferBudget
	charged int64
}

func (b *bodyStore) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refs--
	if b.refs != 0 {
		return nil
	}
	if b.file == nil {
		if b.budget != nil {
			b.budget.Release(b.charged)
			b.charged = 0
		}
		return nil
	}
	err := b.file.Close()
	removeErr := os.Remove(b.file.Name())
	if removeErr == nil && b.budget != nil {
		b.budget.Release(b.charged)
		b.charged = 0
	}
	if err != nil {
		return err
	}
	return removeErr
}

type bodyView struct {
	io.Reader
	owner *bodyStore
	once  sync.Once
}

func (v *bodyView) Close() error {
	var err error
	v.once.Do(func() { err = v.owner.Close() })
	return err
}
func (b *bodyStore) view() io.ReadCloser {
	b.mu.Lock()
	b.refs++
	b.mu.Unlock()
	return &bodyView{Reader: b.reader(), owner: b}
}

func (b *bodyStore) reader() io.Reader {
	if b.file != nil {
		return io.NewSectionReader(b.file, 0, b.size)
	}
	return bytes.NewReader(b.data)
}

func spoolBudget(r io.Reader, max, length int64, budget *firewalltransport.BufferBudget) (_ *bodyStore, err error) {
	if budget == nil {
		return nil, errors.New("spool requires aggregate budget")
	}
	if length > max {
		return nil, rejection{413}
	}
	b := &bodyStore{refs: 1, budget: budget}
	defer func() {
		if err != nil {
			_ = b.Close()
		}
	}()
	bufSize := min(int64(32<<10), max+1)
	if length >= 0 {
		bufSize = min(bufSize, length+1)
	}
	if budget != nil {
		if !budget.Acquire(bufSize) {
			return nil, rejection{503}
		}
		defer budget.Release(bufSize)
	}
	buf := make([]byte, int(bufSize))
	emptyReads := 0
	for {
		n, readErr := r.Read(buf)
		if n == 0 && readErr == nil {
			emptyReads++
			if emptyReads >= 100 {
				return nil, io.ErrNoProgress
			}
		} else {
			emptyReads = 0
		}
		if n > 0 {
			if b.size+int64(n) > max {
				return nil, rejection{413}
			}
			if length >= 0 && b.size+int64(n) > length {
				return nil, rejection{400}
			}
			if err = b.appendChunk(buf[:n]); err != nil {
				return nil, err
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
	}
	if length >= 0 && b.size != length {
		return nil, io.ErrUnexpectedEOF
	}
	return b, nil
}

func (b *bodyStore) appendChunk(chunk []byte) error {
	next := b.size + int64(len(chunk))
	if b.file == nil && next <= bodyMemoryBytes {
		oldLen := len(b.data)
		if int(next) > cap(b.data) {
			capacity := max(int(next), min(bodyMemoryBytes, 2*cap(b.data)))
			if !b.budget.Acquire(int64(capacity)) {
				return rejection{503}
			}
			grown := make([]byte, int(next), capacity)
			copy(grown, b.data)
			previous := int64(cap(b.data))
			b.data = grown
			b.budget.Release(previous)
			b.charged = int64(capacity)
		} else {
			b.data = b.data[:next]
		}
		copy(b.data[oldLen:], chunk)
	} else if b.file == nil {
		// Disk contents and the memory backing array coexist until both writes finish.
		if !b.budget.Acquire(next) {
			return rejection{503}
		}
		b.charged += next
		var err error
		b.file, err = os.CreateTemp("", "netcap-waf-body-*")
		if err != nil {
			return err
		}
		if _, err = b.file.Write(b.data); err != nil {
			return err
		}
		if _, err = b.file.Write(chunk); err != nil {
			return err
		}
		memory := int64(cap(b.data))
		b.data = nil
		b.budget.Release(memory)
		b.charged -= memory
	} else {
		if !b.budget.Acquire(int64(len(chunk))) {
			return rejection{503}
		}
		b.charged += int64(len(chunk))
		if _, err := b.file.Write(chunk); err != nil {
			return err
		}
	}
	b.size = next
	return nil
}

func spoolBodyBudget(r io.Reader, h http.Header, max, length int64, budget *firewalltransport.BufferBudget) (*bodyStore, error) {
	enc := h.Values("Content-Encoding")
	if len(enc) > 1 || len(enc) == 1 && !strings.EqualFold(strings.TrimSpace(enc[0]), "gzip") {
		return nil, rejection{415}
	}
	wire, err := spoolBudget(r, max, length, budget)
	if err != nil || len(enc) == 0 {
		return wire, err
	}
	defer wire.Close()
	z, err := gzip.NewReader(wire.reader())
	if err != nil {
		return nil, rejection{400}
	}
	defer z.Close()
	b, err := spoolBudget(z, max, -1, budget)
	if err != nil {
		var reject rejection
		if errors.As(err, &reject) {
			return nil, err
		}
		return nil, rejection{400}
	}
	return b, nil
}

// Missing compile-time metadata is conservative, including after policy reload.
func policyRequiresBody(p *policy.Compiled, phase string) bool {
	if c, ok := any(p).(interface{ RequiresBody(string) bool }); ok {
		return c.RequiresBody(phase)
	}
	return true
}

func nativeBody(p *policy.Compiled, phase string, b *bodyStore) (string, error) {
	if !policyRequiresBody(p, phase) {
		return "", nil
	}
	if b.size > NativeBodyBytes {
		return "", rejection{413}
	}
	data := make([]byte, int(b.size))
	_, err := io.ReadFull(b.reader(), data)
	return string(data), err
}

func nativeProjection(p *policy.Compiled, phase string, b *bodyStore) (string, func(), error) {
	noop := func() {}
	if !policyRequiresBody(p, phase) {
		return "", noop, nil
	}
	if b.size > NativeBodyBytes {
		return "", noop, rejection{413}
	}
	charge := 2 * b.size
	if b.budget != nil && !b.budget.Acquire(charge) {
		return "", noop, rejection{503}
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			if b.budget != nil {
				b.budget.Release(charge)
			}
		})
	}
	projection, err := nativeBody(p, phase, b)
	if err != nil {
		release()
		return "", noop, err
	}
	return projection, release, nil
}
