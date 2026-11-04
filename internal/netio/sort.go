package netio

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

type timedRecord interface {
	proto.Message
	GetTimestamp() int64
}

// Runs are merged in pairs so file descriptors and merge memory stay bounded.
func sortedAuditFile(path string, budget int) (result string, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "netcap-sort-")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { _ = os.RemoveAll(dir) }
	defer func() {
		if err != nil {
			_ = os.RemoveAll(dir)
		}
	}()
	r, err := Open(path, 64<<10)
	if err != nil {
		return "", nil, err
	}
	defer r.Close()
	h, err := r.ReadHeader()
	if err != nil {
		return "", nil, err
	}
	if _, ok := InitRecord(h.Type).(timedRecord); !ok {
		return "", nil, fmt.Errorf("%s has no sortable timestamp", h.Type)
	}
	var runs []string
	for {
		var records []timedRecord
		used := 0
		for used < budget {
			rec := InitRecord(h.Type).(timedRecord)
			err = r.Next(rec)
			if errors.Is(err, io.EOF) {
				err = nil
				break
			}
			if err != nil {
				return "", nil, err
			}
			records = append(records, rec)
			used += proto.Size(rec) + 64
		}
		if len(records) == 0 {
			break
		}
		sort.SliceStable(records, func(i, j int) bool { return records[i].GetTimestamp() < records[j].GetTimestamp() })
		name := filepath.Join(dir, fmt.Sprintf("run-%d.ncap", len(runs)))
		if err = writeSortedRun(name, h, records); err != nil {
			return "", nil, err
		}
		runs = append(runs, name)
	}
	if len(runs) == 0 {
		name := filepath.Join(dir, "empty.ncap")
		err = writeSortedRun(name, h, nil)
		return name, cleanup, err
	}
	for pass := 0; len(runs) > 1; pass++ {
		var next []string
		for i := 0; i < len(runs); i += 2 {
			if i+1 == len(runs) {
				next = append(next, runs[i])
				break
			}
			name := filepath.Join(dir, fmt.Sprintf("merge-%d-%d.ncap", pass, i))
			if err = mergeSortedRuns(name, h, runs[i], runs[i+1]); err != nil {
				return "", nil, err
			}
			_ = os.Remove(runs[i])
			_ = os.Remove(runs[i+1])
			next = append(next, name)
		}
		runs = next
	}
	return runs[0], cleanup, nil
}

func writeSortedRun(path string, h *types.Header, records []timedRecord) (err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	b := bufio.NewWriterSize(f, 64<<10)
	w := delimited.NewWriter(b)
	if err = w.PutProto(h); err != nil {
		return err
	}
	for _, r := range records {
		if err = w.PutProto(r); err != nil {
			return err
		}
	}
	return b.Flush()
}

func mergeSortedRuns(path string, h *types.Header, left, right string) (err error) {
	var readers [2]*Reader
	for i, p := range []string{left, right} {
		r, e := Open(p, 64<<10)
		if e != nil {
			return e
		}
		readers[i] = r
		defer r.Close()
		if _, e = r.ReadHeader(); e != nil {
			return e
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	b := bufio.NewWriterSize(f, 64<<10)
	w := delimited.NewWriter(b)
	if err = w.PutProto(h); err != nil {
		return err
	}
	var heads [2]timedRecord
	advance := func(i int) error {
		r := InitRecord(h.Type).(timedRecord)
		e := readers[i].Next(r)
		if errors.Is(e, io.EOF) {
			heads[i] = nil
			return nil
		}
		heads[i] = r
		return e
	}
	for i := range readers {
		if err = advance(i); err != nil {
			return err
		}
	}
	for heads[0] != nil || heads[1] != nil {
		i := 0
		if heads[0] == nil || heads[1] != nil && heads[1].GetTimestamp() < heads[0].GetTimestamp() {
			i = 1
		}
		if err = w.PutProto(heads[i]); err != nil {
			return err
		}
		if err = advance(i); err != nil {
			return err
		}
	}
	return b.Flush()
}
