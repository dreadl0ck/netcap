package flowexport

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sync"
)

type Event struct {
	Kind        string       `json:"kind"`
	Observation *Observation `json:"observation,omitempty"`
	Issue       *Issue       `json:"issue,omitempty"`
	Envelope    *Envelope    `json:"envelope,omitempty"`
	Datagram    []byte       `json:"datagram,omitempty"`
	SHA256      string       `json:"sha256,omitempty"`
}

type RecorderHealth struct {
	Health
	Status        string `json:"status"`
	StorageErrors uint64 `json:"storageErrors"`
	Issues        uint64 `json:"issues"`
	RecordsSHA256 string `json:"recordsSHA256,omitempty"`
}

type Recorder struct {
	mu            sync.Mutex
	engine        *Engine
	file          *os.File
	buffer        *bufio.Writer
	path          string
	closed        bool
	storageErrors uint64
	issues        uint64
	digest        hash.Hash
}

func NewRecorder(directory string, config Config) (*Recorder, error) {
	engine, err := New(config)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(directory, "FlowExportsHealth.json")
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("flow-export health already exists")
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(directory, "FlowExports.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	digest := sha256.New()
	r := &Recorder{engine: engine, file: file, buffer: bufio.NewWriterSize(io.MultiWriter(file, digest), 256<<10), path: path, digest: digest}
	if err := r.writeHealth("running"); err != nil {
		file.Close()
		os.Remove(file.Name())
		return nil, err
	}
	return r, nil
}

func (r *Recorder) Observe(data []byte, envelope Envelope) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return fmt.Errorf("flow-export recorder closed")
	}
	batch, decodeErr := r.engine.Decode(data, envelope)
	if decodeErr != nil {
		batch.Issues = append(batch.Issues, Issue{Code: "malformed-export", Envelope: envelope, Detail: decodeErr.Error()})
	}
	r.issues += uint64(len(batch.Issues))
	encoder := json.NewEncoder(r.buffer)
	digest := sha256.Sum256(data)
	if err := encoder.Encode(Event{Kind: "datagram", Envelope: &envelope, Datagram: data, SHA256: hex.EncodeToString(digest[:])}); err != nil {
		r.storageErrors++
		return err
	}
	for i := range batch.Observations {
		if err := encoder.Encode(Event{Kind: "observation", Observation: &batch.Observations[i]}); err != nil {
			r.storageErrors++
			return err
		}
	}
	for i := range batch.Issues {
		if err := encoder.Encode(Event{Kind: "issue", Issue: &batch.Issues[i]}); err != nil {
			r.storageErrors++
			return err
		}
	}
	return nil
}

func (r *Recorder) Flush() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	if err := r.buffer.Flush(); err != nil {
		r.storageErrors++
		return err
	}
	return r.writeHealth("running")
}

func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var first error
	for _, operation := range []func() error{r.buffer.Flush, r.file.Sync, r.file.Close} {
		if err := operation(); err != nil {
			r.storageErrors++
			if first == nil {
				first = err
			}
		}
	}
	health := r.engine.Health()
	status := "done"
	if r.storageErrors > 0 {
		status = "error"
	} else if r.issues > 0 || health.Malformed+health.MissingTemplates+health.SequenceDiscontinuities+health.PossibleRestarts+health.StateLimitExceeded > 0 {
		status = "partial"
	}
	if err := r.writeHealth(status); err != nil && first == nil {
		first = err
	}
	return first
}

func (r *Recorder) writeHealth(status string) error {
	data, err := json.Marshal(RecorderHealth{Health: r.engine.Health(), Status: status, StorageErrors: r.storageErrors, Issues: r.issues, RecordsSHA256: hex.EncodeToString(r.digest.Sum(nil))})
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(r.path), ".flow-health-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), r.path)
}
