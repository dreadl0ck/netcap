package flow

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/types"
)

type FileResult struct {
	Result
	RecordFileSHA256 string `json:"recordFileSHA256"`
	RecordType       string `json:"recordType"`
}

// ReadFile fails on unavailable, malformed, changing or ambiguous telemetry.
func ReadFile(ctx context.Context, path string, query Query) (FileResult, error) {
	var response FileResult
	if err := ctx.Err(); err != nil {
		return response, err
	}
	if err := validQuery(query); err != nil {
		return response, err
	}
	file, err := os.Open(path)
	if err != nil {
		return response, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return response, err
	}
	if !before.Mode().IsRegular() {
		return response, fmt.Errorf("flow input must be a regular file")
	}
	digest := sha256.New()
	var input io.Reader = io.TeeReader(file, digest)
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(input)
		if err != nil {
			return response, err
		}
		defer gz.Close()
		input = gz
	}
	reader := delimited.NewReaderWithLimit(&decodedBudgetReader{input: input, remaining: 256 << 20}, 4<<20)
	var header types.Header
	if err := reader.NextProto(&header); err != nil {
		return response, err
	}
	if header.Type != types.Type_NC_Connection {
		return response, fmt.Errorf("expected Connection telemetry, found %s", header.Type)
	}
	dataset := NewDataset(100000)
	for ordinal := uint64(0); ; ordinal++ {
		if err := ctx.Err(); err != nil {
			return response, err
		}
		var record types.Connection
		err := reader.NextProto(&record)
		if err == io.EOF {
			break
		}
		if err != nil {
			return response, fmt.Errorf("connection record %d: %w", ordinal, err)
		}
		if ordinal >= 1000000 {
			return response, fmt.Errorf("flow input record limit exceeded: 1000000")
		}
		if err := dataset.Add(&record, ordinal); err != nil {
			return response, err
		}
	}
	after, err := file.Stat()
	if err != nil {
		return response, err
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return response, fmt.Errorf("analysis records changed during query")
	}
	response.Result, err = dataset.Query(ctx, query)
	if err != nil {
		return response, err
	}
	response.RecordFileSHA256 = hex.EncodeToString(digest.Sum(nil))
	response.RecordType = "Connection"
	return response, nil
}

type decodedBudgetReader struct {
	input     io.Reader
	remaining int64
}

func (r *decodedBudgetReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.remaining == 0 {
		var extra [1]byte
		n, err := r.input.Read(extra[:])
		if n > 0 {
			return 0, fmt.Errorf("flow decoded byte limit exceeded: 268435456")
		}
		return 0, err
	}
	if int64(len(p)) > r.remaining {
		p = p[:int(r.remaining)]
	}
	n, err := r.input.Read(p)
	r.remaining -= int64(n)
	return n, err
}
