package rules

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/types"
)

const OfflineReadyFile = "audit-output-ready.json"
const OfflineLeaseFile = ".offline-rule-evaluation.lock"

type OfflineReadyMarker struct {
	Version int    `json:"version"`
	RunID   string `json:"runId"`
}

// OfflineLease coordinates evaluators and parent reanalysis. Stale locks require
// explicit operator removal; deleting a live owner's lock is never automatic.
type OfflineLease struct {
	root *os.Root
	once sync.Once
	err  error
}

func AcquireOfflineLease(directory string) (*OfflineLease, error) {
	r, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	f, err := r.OpenFile(OfflineLeaseFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		r.Close()
		return nil, fmt.Errorf("offline directory is leased or unavailable: %w", err)
	}
	if err := f.Close(); err != nil {
		r.Remove(OfflineLeaseFile)
		r.Close()
		return nil, err
	}
	return &OfflineLease{root: r}, nil
}

func (l *OfflineLease) Close() error {
	l.once.Do(func() { l.err = errors.Join(l.root.Remove(OfflineLeaseFile), l.root.Close()) })
	return l.err
}

func offlineHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

type offlineSnapshot struct {
	OfflineFile
	info os.FileInfo
}
type offlineRow struct {
	record    types.AuditRecord
	canonical []byte
	hash      string
	ordinal   uint64
	timestamp int64
	file      string
}

func offlineOpen(root *os.Root, name string) (*os.File, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("offline input %s must be a regular non-symlink file", name)
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(info, after) {
		f.Close()
		return nil, fmt.Errorf("offline input %s changed while opening", name)
	}
	return f, nil
}

func offlineMetadata(ctx context.Context, root *os.Root, name string) ([]byte, offlineSnapshot, error) {
	f, err := offlineOpen(root, name)
	if err != nil {
		return nil, offlineSnapshot{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, offlineSnapshot{}, err
	}
	b, err := io.ReadAll(&offlineBudgetReader{ctx: ctx, input: f, remaining: 16 << 20})
	if err != nil {
		return nil, offlineSnapshot{}, err
	}
	if !utf8.Valid(b) {
		return nil, offlineSnapshot{}, fmt.Errorf("invalid UTF-8 metadata: %s", name)
	}
	return b, offlineSnapshot{OfflineFile: OfflineFile{name, offlineHash(b), info.Size()}, info: info}, nil
}

func offlineAdmission(ctx context.Context, root *os.Root) (evidence.CaptureManifest, []offlineSnapshot, error) {
	var m evidence.CaptureManifest
	b, manifest, err := offlineMetadata(ctx, root, "capture-manifest.json")
	if err != nil {
		return m, nil, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, nil, err
	}
	if m.Version != 1 || m.RunID == "" || len(m.RunID) > 256 || (m.Status != "done" && m.Status != "partial" && m.Status != "complete" && m.Status != "stopped") || m.Error != "" {
		return m, nil, fmt.Errorf("offline evaluation requires a finalized done/partial/stopped version 1 capture manifest with runId")
	}
	b, marker, err := offlineMetadata(ctx, root, OfflineReadyFile)
	if err != nil {
		return m, nil, fmt.Errorf("audit output is not ready: %w", err)
	}
	var ready OfflineReadyMarker
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&ready); err != nil {
		return m, nil, err
	}
	var extra any
	if d.Decode(&extra) != io.EOF || ready.Version != 1 || ready.RunID != m.RunID {
		return m, nil, fmt.Errorf("audit ready marker does not match capture")
	}
	if m.Config.Kind == "file" && m.Config.BPF != "" {
		return m, nil, fmt.Errorf("offline BPF capture withholds interface scope")
	}
	l := m.CommunityScopes
	if l == nil || l.Schema != 1 || !l.Complete || l.Overflow != 0 || len(l.Entries) == 0 || len(l.Entries) > evidence.MaxCommunityScopes {
		return m, nil, fmt.Errorf("offline evaluation requires finalized qualified scopes")
	}
	var scope *evidence.FlowScope
	seen := map[string]bool{}
	for _, e := range l.Entries {
		if e.Ambiguous || e.Scope.Sensor == "" || len(e.Scope.Sensor) > 64 || e.Scope.InterfaceIndex < 0 || len(e.Scope.VLANs) > 4 || !strings.HasPrefix(e.CommunityID, "1:") || len(e.CommunityID) > 128 || seen[e.CommunityID] {
			return m, nil, fmt.Errorf("ambiguous or invalid offline scope")
		}
		for _, v := range e.Scope.VLANs {
			if v > 4095 {
				return m, nil, fmt.Errorf("invalid offline VLAN")
			}
		}
		seen[e.CommunityID] = true
		if scope != nil && (scope.Sensor != e.Scope.Sensor || scope.InterfaceIndex != e.Scope.InterfaceIndex || !slices.Equal(scope.VLANs, e.Scope.VLANs)) {
			return m, nil, fmt.Errorf("offline evaluation requires a single unambiguous scope")
		}
		scope = &e.Scope
	}
	return m, []offlineSnapshot{manifest, marker}, nil
}

type offlineBudgetReader struct {
	ctx       context.Context
	input     io.Reader
	remaining int64
}

func (r *offlineBudgetReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	if r.remaining == 0 {
		var extra [1]byte
		n, err := r.input.Read(extra[:])
		if n > 0 {
			return 0, fmt.Errorf("offline decoded byte limit exceeded")
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

func offlineValidValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Interface, reflect.Pointer:
		return v.IsNil() || offlineValidValue(v.Elem())
	case reflect.String:
		return utf8.ValidString(v.String())
	case reflect.Float32, reflect.Float64:
		return !math.IsNaN(v.Float()) && !math.IsInf(v.Float(), 0)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if !offlineValidValue(v.Field(i)) {
				return false
			}
		}
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return true
		}
		for i := 0; i < v.Len(); i++ {
			if !offlineValidValue(v.Index(i)) {
				return false
			}
		}
	case reflect.Map:
		it := v.MapRange()
		for it.Next() {
			if !offlineValidValue(it.Key()) || !offlineValidValue(it.Value()) {
				return false
			}
		}
	}
	return true
}

func offlineReadType(ctx context.Context, root *os.Root, typ string, limits OfflineLimits, remaining *int64, total *int64) ([]offlineRow, *offlineSnapshot, OfflineTypeStats, error) {
	stats := OfflineTypeStats{Type: typ}
	var name string
	for _, candidate := range []string{typ + ".ncap", typ + ".ncap.gz"} {
		_, err := root.Lstat(candidate)
		if err == nil {
			if name != "" {
				return nil, nil, stats, fmt.Errorf("ambiguous %s audit input", typ)
			}
			name = candidate
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, nil, stats, err
		}
	}
	if name == "" {
		stats.Missing = true
		return nil, nil, stats, nil
	}
	f, err := offlineOpen(root, name)
	if err != nil {
		return nil, nil, stats, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, stats, err
	}
	if info.Size() > 256<<20 {
		return nil, nil, stats, fmt.Errorf("offline audit file exceeds 256 MiB")
	}
	h := sha256.New()
	var input io.Reader = io.TeeReader(&offlineBudgetReader{ctx: ctx, input: f, remaining: 256 << 20}, h)
	if strings.HasSuffix(name, ".gz") {
		gz, err := gzip.NewReader(input)
		if err != nil {
			return nil, nil, stats, err
		}
		defer gz.Close()
		input = gz
	}
	budget := &offlineBudgetReader{ctx: ctx, input: input, remaining: *remaining}
	reader := delimited.NewReaderWithLimit(budget, uint64(limits.FrameBytes))
	var header types.Header
	if err := reader.NextProto(&header); err != nil {
		return nil, nil, stats, fmt.Errorf("%s header: %w", name, err)
	}
	if header.Type != offlineType(typ) {
		return nil, nil, stats, fmt.Errorf("%s has incorrect header type %s", name, header.Type)
	}
	rows := []offlineRow{}
	var sortBytes int64
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, stats, err
		}
		record := offlineRecord(typ)
		err := reader.NextProto(record.(proto.Message))
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, stats, fmt.Errorf("%s record %d: %w", name, len(rows), err)
		}
		*total++
		if *total > limits.Records {
			return nil, nil, stats, fmt.Errorf("offline record limit exceeded")
		}
		if record.Time() <= 0 {
			return nil, nil, stats, fmt.Errorf("%s record %d: timestamp must be positive", name, len(rows))
		}
		if !offlineValidValue(reflect.ValueOf(record)) {
			return nil, nil, stats, fmt.Errorf("%s record contains invalid UTF-8 or nonfinite number", name)
		}
		canonical, err := json.Marshal(record)
		if err != nil {
			return nil, nil, stats, err
		}
		// Include retained decoded allocations, JSON, both sort buffers and slack.
		sortBytes += offlineMemory(reflect.ValueOf(record)) + int64(len(canonical))*2 + 1024
		if sortBytes > limits.SortBytes {
			return nil, nil, stats, fmt.Errorf("offline per-type sort byte limit exceeded")
		}
		rows = append(rows, offlineRow{record: record, canonical: canonical, hash: offlineHash(canonical), ordinal: uint64(len(rows)), timestamp: record.Time(), file: name})
		stats.Records++
		stats.CanonicalBytes += int64(len(canonical))
	}
	*remaining = budget.remaining
	after, err := f.Stat()
	if err != nil {
		return nil, nil, stats, err
	}
	if !offlineSameInfo(info, after) {
		return nil, nil, stats, fmt.Errorf("offline source changed: %s", name)
	}
	snapshot := &offlineSnapshot{OfflineFile: OfflineFile{name, hex.EncodeToString(h.Sum(nil)), info.Size()}, info: info}
	if err := offlineSort(ctx, rows); err != nil {
		return nil, nil, stats, err
	}
	return rows, snapshot, stats, nil
}

func offlineMemory(v reflect.Value) int64 {
	n := int64(v.Type().Size())
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			n += offlineMemory(v.Elem())
		}
	case reflect.String:
		n += int64(v.Len())
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			n += offlineMemory(v.Field(i)) - int64(v.Field(i).Type().Size())
		}
	case reflect.Slice:
		n += int64(v.Cap()) * int64(v.Type().Elem().Size())
		if v.Type().Elem().Kind() != reflect.Uint8 {
			for i := 0; i < v.Len(); i++ {
				n += offlineMemory(v.Index(i)) - int64(v.Index(i).Type().Size())
			}
		}
	case reflect.Map:
		n += 256
		it := v.MapRange()
		for it.Next() {
			n += offlineMemory(it.Key()) + offlineMemory(it.Value()) + 64
		}
	}
	return n
}

func offlineSort(ctx context.Context, rows []offlineRow) error {
	return offlineSortValues(ctx, rows, func(a, b offlineRow) bool {
		if a.timestamp != b.timestamp {
			return a.timestamp < b.timestamp
		}
		if a.hash != b.hash {
			return a.hash < b.hash
		}
		return bytes.Compare(a.canonical, b.canonical) < 0
	})
}

func offlineSortValues[T any](ctx context.Context, values []T, less func(T, T) bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	temp := make([]T, len(values))
	for width := 1; width < len(values); width *= 2 {
		for start := 0; start < len(values); start += width * 2 {
			if err := ctx.Err(); err != nil {
				return err
			}
			mid, end := min(start+width, len(values)), min(start+width*2, len(values))
			i, j := start, mid
			for k := start; k < end; k++ {
				if k%1024 == 0 {
					if err := ctx.Err(); err != nil {
						return err
					}
				}
				if i < mid && (j >= end || !less(values[j], values[i])) {
					temp[k] = values[i]
					i++
				} else {
					temp[k] = values[j]
					j++
				}
			}
		}
		copy(values, temp)
	}
	return ctx.Err()
}

func offlineSameInfo(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime()) && a.Mode() == b.Mode()
}

func offlineRevalidate(ctx context.Context, root *os.Root, snapshots []offlineSnapshot) error {
	for _, s := range snapshots {
		f, err := offlineOpen(root, s.Name)
		if err != nil {
			return err
		}
		before, err := f.Stat()
		if err != nil {
			f.Close()
			return err
		}
		h := sha256.New()
		_, readErr := io.Copy(h, &offlineBudgetReader{ctx: ctx, input: f, remaining: 256 << 20})
		after, statErr := f.Stat()
		closeErr := f.Close()
		if err := errors.Join(readErr, statErr, closeErr); err != nil {
			return err
		}
		if !offlineSameInfo(s.info, before) || !offlineSameInfo(before, after) || hex.EncodeToString(h.Sum(nil)) != s.SHA256 {
			return fmt.Errorf("offline source changed: %s", s.Name)
		}
	}
	return ctx.Err()
}

func offlineSafeDirectory(directory string) (string, error) {
	a, err := filepath.Abs(directory)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(a)
}

func offlineValidateAlertHistory(ctx context.Context, file *os.File) error {
	gz, err := gzip.NewReader(&offlineBudgetReader{ctx: ctx, input: file, remaining: 256 << 20})
	if err != nil {
		return err
	}
	defer gz.Close()
	reader := delimited.NewReaderWithLimit(&offlineBudgetReader{ctx: ctx, input: gz, remaining: 256 << 20}, maxAlertRecordSize)
	var header types.Header
	if err := reader.NextProto(&header); err != nil {
		return err
	}
	if header.Type != types.Type_NC_Alert {
		return fmt.Errorf("invalid alert history header")
	}
	for count := 0; ; count++ {
		var a types.Alert
		err := reader.NextProto(&a)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if count >= 1000000 {
			return fmt.Errorf("offline alert history record limit exceeded")
		}
	}
}
