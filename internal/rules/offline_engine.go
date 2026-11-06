package rules

import (
	"container/heap"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/expr-lang/expr"

	"github.com/dreadl0ck/netcap/types"
)

type offlineGroup struct {
	key            string
	values         map[string]any
	queue          []int
	head, n, index int
	first          int64
	charge         int64
}
type offlineGroups []*offlineGroup

func (h offlineGroups) Len() int { return len(h) }
func (h offlineGroups) Less(i, j int) bool {
	if h[i].first != h[j].first {
		return h[i].first < h[j].first
	}
	return h[i].key < h[j].key
}
func (h offlineGroups) Swap(i, j int) { h[i], h[j] = h[j], h[i]; h[i].index = i; h[j].index = j }
func (h *offlineGroups) Push(x any)   { g := x.(*offlineGroup); g.index = len(*h); *h = append(*h, g) }
func (h *offlineGroups) Pop() any {
	a := *h
	g := a[len(a)-1]
	a[len(a)-1] = nil
	*h = a[:len(a)-1]
	return g
}

type offlineRuleState struct {
	compiled       offlineCompiled
	stats          *OfflineRuleStats
	groups         map[string]*offlineGroup
	expiry         offlineGroups
	pending        int64
	reservedGroups int64
}
type offlineJobState struct {
	groups, pending, bytes, alertBytes int64
	alerts                             []*types.Alert
}

func offlineGroupKey(c offlineCompiled, record types.AuditRecord) (string, map[string]any, bool, error) {
	v := reflect.ValueOf(record).Elem()
	key := make([]byte, 0, 128)
	values := make(map[string]any, len(c.fields))
	for i, index := range c.fields {
		f := v.Field(index)
		var s string
		switch k := f.Kind(); {
		case k == reflect.String:
			s = f.String()
			if s == "" {
				return "", nil, false, nil
			}
		case k >= reflect.Int && k <= reflect.Int64:
			s = strconv.FormatInt(f.Int(), 10)
		default:
			s = strconv.FormatUint(f.Uint(), 10)
		}
		if len(s) > 1024 || len(key)+5+len(s) > 1024 {
			return "", nil, false, fmt.Errorf("offline group key exceeds 1024 bytes")
		}
		key = append(key, byte(f.Kind()))
		key = binary.BigEndian.AppendUint32(key, uint32(len(s)))
		key = append(key, s...)
		if f.Kind() == reflect.String {
			values[c.rule.Threshold.GroupBy[i]] = s
		} else {
			values[c.rule.Threshold.GroupBy[i]] = offlineInteger{Type: f.Type().String(), Value: s}
		}
	}
	return string(key), values, true, nil
}

func (s *offlineRuleState) remove(g *offlineGroup, job *offlineJobState) {
	heap.Remove(&s.expiry, g.index)
	delete(s.groups, g.key)
	s.pending -= int64(g.n)
	job.pending -= int64(g.n)
	job.groups--
	job.bytes -= g.charge
}

func (s *offlineRuleState) expire(ctx context.Context, now int64, rows []offlineRow, job *offlineJobState) error {
	cutoff := now - s.compiled.window
	for len(s.expiry) > 0 && s.expiry[0].first < cutoff {
		if err := ctx.Err(); err != nil {
			return err
		}
		g := s.expiry[0]
		for g.n > 0 && rows[g.queue[g.head]].timestamp < cutoff {
			g.head = (g.head + 1) % len(g.queue)
			g.n--
			s.pending--
			job.pending--
		}
		if g.n == 0 {
			s.remove(g, job)
		} else {
			g.first = rows[g.queue[g.head]].timestamp
			heap.Fix(&s.expiry, g.index)
		}
	}
	return nil
}

func offlineFeed(ctx context.Context, s *offlineRuleState, rowIndex int, rows []offlineRow, job *offlineJobState, report *OfflineReport) error {
	row := rows[rowIndex]
	if err := s.expire(ctx, row.timestamp, rows, job); err != nil {
		return err
	}
	match, err := expr.Run(s.compiled.program, offlineEnvironment(row.record))
	if err != nil {
		return err
	}
	if match != true {
		return nil
	}
	s.stats.Matches++
	key, values, ok, err := offlineGroupKey(s.compiled, row.record)
	if err != nil {
		return err
	}
	if !ok {
		s.stats.MissingGroups++
		return nil
	}
	g := s.groups[key]
	limits := report.Limits
	if g == nil {
		charge := int64(len(key))*2 + int64(s.compiled.rule.Threshold.Count)*8 + 2048
		growth := int64(0)
		if int64(len(s.groups))+1 > s.reservedGroups {
			growth = 256
		}
		if int64(len(s.groups))+1 > limits.GroupsPerRule || job.groups+1 > limits.Groups || job.bytes+charge+growth > limits.StateBytes {
			return fmt.Errorf("offline group/state limit exceeded")
		}
		g = &offlineGroup{key: key, values: values, queue: make([]int, s.compiled.rule.Threshold.Count), charge: charge, first: row.timestamp}
		s.groups[key] = g
		heap.Push(&s.expiry, g)
		job.groups++
		job.bytes += charge
		if growth != 0 {
			s.reservedGroups++
			job.bytes += growth
		}
	}
	if s.pending+1 > limits.PendingPerRule || job.pending+1 > limits.Pending {
		return fmt.Errorf("offline pending match limit exceeded")
	}
	g.queue[(g.head+g.n)%len(g.queue)] = rowIndex
	g.n++
	s.pending++
	job.pending++
	if g.n < s.compiled.rule.Threshold.Count {
		return nil
	}
	alert, err := offlineAlert(s.compiled, g, rows, report)
	if err != nil {
		return err
	}
	charge := int64(alert.Size()) + 512
	if int64(len(job.alerts))+1 > limits.Alerts || job.alertBytes+charge > limits.AlertBytes {
		return fmt.Errorf("offline alert limit exceeded")
	}
	job.alerts = append(job.alerts, alert)
	job.alertBytes += charge
	s.stats.Alerts++
	s.remove(g, job)
	return nil
}

func offlineAlert(c offlineCompiled, g *offlineGroup, rows []offlineRow, report *OfflineReport) (*types.Alert, error) {
	first := rows[g.queue[g.head]]
	last := rows[g.queue[(g.head+g.n-1)%len(g.queue)]]
	refs := make([]OfflineContributor, 0, 16)
	for i := 0; i < g.n && i < 16; i++ {
		index := i
		if g.n > 16 && i == 15 {
			index = g.n - 1
		}
		r := rows[g.queue[(g.head+index)%len(g.queue)]]
		refs = append(refs, OfflineContributor{File: r.file, Ordinal: r.ordinal, SHA256: r.hash, Timestamp: r.timestamp})
	}
	meta := OfflineAlertMetadata{Version: 1, RunID: report.RunID, RuleID: c.rule.ID, RuleDigest: c.digest, Group: g.values, Count: g.n, First: first.timestamp, Last: last.timestamp, WindowNs: c.window, Contributors: refs, ContributorsTruncated: g.n > 16}
	// Event IDs are filled after the canonical input digest is finalized.
	b, err := json.Marshal(map[string]OfflineAlertMetadata{"netcapOffline": meta})
	if err != nil {
		return nil, err
	}
	a := &types.Alert{Timestamp: last.timestamp, Name: c.rule.Name, Description: c.rule.Description, RuleName: c.rule.Name, RecordType: c.rule.Type, Severity: c.rule.Severity, MatchedRecord: string(last.canonical), RuleExpression: c.rule.Expression, Threshold: int32(g.n), ThresholdWindow: int32(c.window / int64(time.Second)), DetectedAt: time.Now().UnixNano(), RuleDigest: c.digest, MatchedRecordSHA256: last.hash, TimestampBasis: "record", Notes: string(b)}
	v := reflect.ValueOf(last.record).Elem()
	get := func(name string) string {
		f := v.FieldByName(name)
		if !f.IsValid() {
			return ""
		}
		return fmt.Sprint(f.Interface())
	}
	a.SrcIP = get("SrcIP")
	a.DstIP = get("DstIP")
	a.SrcPort = get("SrcPort")
	a.DstPort = get("DstPort")
	a.CommunityID = get("CommunityID")
	a.Protocol = c.rule.Type
	return a, nil
}

func offlineDigestPart(h hash.Hash, b []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(b)))
	h.Write(size[:])
	h.Write(b)
}

// EvaluateOffline validates and evaluates all input before appending any alert.
// Errors before committing publish nothing. A publish-failed report records the
// durable prefix; callers must never automatically retry a failed publication.
func EvaluateOffline(ctx context.Context, request OfflineRequest) (*OfflineReport, error) {
	started := time.Now()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	limits, err := normalizeOfflineLimits(request.Limits)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, limits.Duration)
	defer cancel()
	compiled, err := compileOfflinePack(request.Pack)
	if err != nil {
		return nil, err
	}
	if int64(len(compiled)) > limits.Rules {
		return nil, fmt.Errorf("offline rule limit exceeded")
	}
	sort.Slice(compiled, func(i, j int) bool {
		a, b := compiled[i].rule, compiled[j].rule
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.ID < b.ID
	})
	directory, err := offlineSafeDirectory(request.Directory)
	if err != nil {
		return nil, err
	}
	lease, err := AcquireOfflineLease(directory)
	if err != nil {
		return nil, err
	}
	defer lease.Close()
	root := lease.root
	history, err := listOfflineEvaluations(ctx, directory)
	if err != nil {
		return nil, err
	}
	if len(history) >= 100 {
		return nil, fmt.Errorf("offline report history limit exceeded: 100")
	}
	manifest, snapshots, err := offlineAdmission(ctx, root)
	if err != nil {
		return nil, err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	report := &OfflineReport{Version: 1, ID: hex.EncodeToString(random[:]), RunID: manifest.RunID, StartedAt: started.UTC().Format(time.RFC3339Nano), Limits: limits, Status: "committing", Limitations: []string{"retained-records-only; ordinary audit filter provenance is unknown", "single finalized scope; no actions, sequence, distinct, rate limit or wall-clock deduplication"}}
	config, _ := json.Marshal(manifest.Config)
	report.ConfigDigest = offlineHash(config)
	// Observation policy excludes execution, source location and storage knobs.
	policy, _ := json.Marshal(struct {
		Kind            string `json:"kind"`
		BPF             string `json:"bpf"`
		SnapLen         int    `json:"snapLen"`
		IncludeDecoders string `json:"includeDecoders"`
		ExcludeDecoders string `json:"excludeDecoders"`
		Reassembly      bool   `json:"reassembly"`
	}{manifest.Config.Kind, manifest.Config.BPF, manifest.Config.SnapLen, manifest.Config.IncludeDecoders, manifest.Config.ExcludeDecoders, manifest.Config.Reassembly})
	report.ObservationPolicyDigest = offlineHash(policy)
	packRules := make([]OfflineRule, len(compiled))
	report.Rules = make([]OfflineRuleStats, len(compiled))
	for i, c := range compiled {
		packRules[i] = c.rule
		report.Rules[i] = OfflineRuleStats{ID: c.rule.ID, Type: c.rule.Type, Digest: c.digest, Enabled: c.rule.Enabled}
	}
	b, _ := json.Marshal(OfflinePack{Format: OfflineFormat, Rules: packRules})
	report.PackDigest = offlineHash(b)
	inputDigest := sha256.New()
	remaining, total := limits.DecodedBytes, int64(0)
	job := &offlineJobState{}
	partial := manifest.Status == "partial" || manifest.Status == "stopped" || manifest.QueueDrops > 0 || manifest.TruncatedPackets > 0 || (manifest.KernelDrops != nil && *manifest.KernelDrops > 0)
	scopes := map[string]bool{}
	for _, entry := range manifest.CommunityScopes.Entries {
		scopes[entry.CommunityID] = true
	}
	for start := 0; start < len(compiled); {
		end := start + 1
		for end < len(compiled) && compiled[end].rule.Type == compiled[start].rule.Type {
			end++
		}
		active := false
		for _, c := range compiled[start:end] {
			active = active || c.rule.Enabled
		}
		if !active {
			start = end
			continue
		}
		typ := compiled[start].rule.Type
		rows, snapshot, stats, err := offlineReadType(ctx, root, typ, limits, &remaining, &total)
		if err != nil {
			return nil, err
		}
		report.Types = append(report.Types, stats)
		if snapshot != nil {
			snapshots = append(snapshots, *snapshot)
		}
		offlineDigestPart(inputDigest, []byte(typ))
		if stats.Missing {
			partial = true
			offlineDigestPart(inputDigest, []byte("missing"))
		}
		states := make([]*offlineRuleState, 0, end-start)
		for i := start; i < end; i++ {
			if compiled[i].rule.Enabled {
				states = append(states, &offlineRuleState{compiled: compiled[i], stats: &report.Rules[i], groups: map[string]*offlineGroup{}})
			}
		}
		for i, row := range rows {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			offlineDigestPart(inputDigest, row.canonical)
			cid := reflect.ValueOf(row.record).Elem().FieldByName("CommunityID").String()
			if !scopes[cid] {
				report.Types[len(report.Types)-1].UnknownScopes++
				partial = true
				continue
			}
			for _, s := range states {
				if err := offlineFeed(ctx, s, i, rows, job, report); err != nil {
					return nil, fmt.Errorf("rule %s: %w", s.compiled.rule.ID, err)
				}
			}
		}
		for _, s := range states {
			if s.stats.MissingGroups > 0 {
				partial = true
			}
		}
		job.groups = 0
		job.pending = 0
		job.bytes = 0
		start = end
	}
	report.InputCanonicalDigest = hex.EncodeToString(inputDigest.Sum(nil))
	report.PlannedAlerts = int64(len(job.alerts))
	// Type/rule/crossing order is independent of expression matching interleaving.
	ruleIDs := map[string]string{}
	for _, c := range compiled {
		ruleIDs[c.digest] = c.rule.ID
	}
	if err := offlineSortValues(ctx, job.alerts, func(a, b *types.Alert) bool {
		if a.RecordType != b.RecordType {
			return a.RecordType < b.RecordType
		}
		return ruleIDs[a.RuleDigest] < ruleIDs[b.RuleDigest]
	}); err != nil {
		return nil, err
	}
	crossings := map[string]int{}
	fileHashes := make(map[string]string, len(snapshots))
	for _, snapshot := range snapshots {
		fileHashes[snapshot.Name] = snapshot.SHA256
	}
	var identityBytes int64
	for _, a := range job.alerts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var envelope map[string]OfflineAlertMetadata
		if err := json.Unmarshal([]byte(a.Notes), &envelope); err != nil {
			return nil, err
		}
		m := envelope["netcapOffline"]
		m.InputCanonicalDigest = report.InputCanonicalDigest
		m.ObservationPolicyDigest = report.ObservationPolicyDigest
		for i := range m.Contributors {
			m.Contributors[i].FileSHA256 = fileHashes[m.Contributors[i].File]
		}
		// Provenance (run, frame ordinal and detection wall time) is excluded.
		group, _ := json.Marshal([]any{m.RuleDigest, m.Group})
		key := string(group)
		if _, exists := crossings[key]; !exists {
			identityBytes += int64(len(key)) + 128
			if job.alertBytes+identityBytes > limits.AlertBytes {
				return nil, fmt.Errorf("offline alert identity byte limit exceeded")
			}
		}
		identity, _ := json.Marshal([]any{report.InputCanonicalDigest, report.ObservationPolicyDigest, report.PackDigest, m.RuleDigest, m.Group, crossings[key], a.Timestamp, a.MatchedRecordSHA256})
		crossings[key]++
		m.EventID = offlineHash(identity)
		envelope["netcapOffline"] = m
		b, _ := json.Marshal(envelope)
		a.Notes = string(b)
	}
	var alertBytes int64
	for _, a := range job.alerts {
		alertBytes += int64(a.Size()) + 512
	}
	if alertBytes+identityBytes > limits.AlertBytes {
		return nil, fmt.Errorf("offline alert byte limit exceeded")
	}
	if err := offlineRevalidate(ctx, root, snapshots); err != nil {
		return nil, err
	}
	// A previously absent type appearing during evaluation changes the input set.
	for _, t := range report.Types {
		for _, name := range []string{t.Type + ".ncap", t.Type + ".ncap.gz"} {
			exists := false
			for _, s := range snapshots {
				if s.Name == name {
					exists = true
				}
			}
			if !exists {
				if _, err := root.Lstat(name); err == nil {
					return nil, fmt.Errorf("offline source set changed: %s", name)
				} else if !errors.Is(err, os.ErrNotExist) {
					return nil, err
				}
			}
		}
	}
	for _, s := range snapshots {
		report.Files = append(report.Files, s.OfflineFile)
	}
	if err := offlinePublish(ctx, directory, root, report, job.alerts, partial, started); err != nil {
		report.Status = "publish-failed"
		report.Error = err.Error()
		report.Elapsed = time.Since(started)
		return report, err
	}
	return report, nil
}

func offlinePublish(ctx context.Context, directory string, root *os.Root, report *OfflineReport, alerts []*types.Alert, partial bool, started time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := root.Mkdir("rule-evaluations", 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := root.Lstat("rule-evaluations")
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("rule-evaluations must be a non-symlink directory")
	}
	fail := func(err error) error {
		report.Status = "publish-failed"
		report.Error = err.Error()
		report.Elapsed = time.Since(started)
		return errors.Join(err, offlineWriteReport(root, report))
	}
	if err := offlineWriteReport(root, report); err != nil {
		return fail(err)
	}
	for _, name := range []string{"Alert.ncap.gz", "Alert.ncap"} {
		info, err := root.Lstat(name)
		if err == nil && !info.Mode().IsRegular() {
			return fail(fmt.Errorf("alert history must be a regular non-symlink file"))
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fail(err)
		}
		if name == "Alert.ncap" && err == nil {
			return fail(fmt.Errorf("uncompressed alert history conflicts with offline append"))
		}
	}
	if len(alerts) > 0 {
		writer, err := newOfflineAlertWriter(ctx, root, directory)
		if err != nil {
			return fail(err)
		}
		for _, a := range alerts {
			if err := ctx.Err(); err != nil {
				return fail(errors.Join(err, writer.Close()))
			}
			if err := writer.WriteAlert(a); err != nil {
				return fail(errors.Join(err, writer.Close()))
			}
			report.CommittedAlerts++
		}
		if err := writer.Close(); err != nil {
			return fail(err)
		}
	}
	report.Status = "complete"
	if partial {
		report.Status = "partial"
	}
	report.Elapsed = time.Since(started)
	if err := offlineWriteReport(root, report); err != nil {
		return fail(err)
	}
	return nil
}

// Reuse FileAlertWriter's durable member append while opening the destination
// through the pinned root. A live legacy writer is an admission conflict.
func newOfflineAlertWriter(ctx context.Context, root *os.Root, directory string) (*FileAlertWriter, error) {
	path := filepath.Join(directory, "Alert.ncap.gz")
	alertStores.Lock()
	defer alertStores.Unlock()
	if alertStores.files[path] != nil {
		return nil, fmt.Errorf("alert history has an active writer")
	}
	var size int64
	var original os.FileInfo
	input, err := offlineOpen(root, "Alert.ncap.gz")
	if err == nil {
		original, err = input.Stat()
		if err == nil && original.Size() > 256<<20 {
			err = fmt.Errorf("offline alert history exceeds 256 MiB")
		}
		if err == nil {
			err = offlineValidateAlertHistory(ctx, input)
		}
		after, statErr := input.Stat()
		err = errors.Join(err, statErr, input.Close())
		if err != nil {
			return nil, err
		}
		if !offlineSameInfo(original, after) {
			return nil, fmt.Errorf("alert history changed during validation")
		}
		size = after.Size()
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	flags := os.O_RDWR | os.O_APPEND
	if original == nil {
		flags |= os.O_CREATE | os.O_EXCL
	}
	f, err := root.OpenFile("Alert.ncap.gz", flags, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() || (original != nil && !offlineSameInfo(original, info)) {
		f.Close()
		return nil, fmt.Errorf("alert history changed before append")
	}
	store := &alertStore{path: path, file: f, size: size, refs: 1}
	alertStores.files[path] = store
	return &FileAlertWriter{store: store}, nil
}

func offlineWriteReport(root *os.Root, report *OfflineReport) error {
	b, err := json.Marshal(report)
	if err != nil {
		return err
	}
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	temp := "rule-evaluations/." + hex.EncodeToString(random[:]) + ".tmp"
	f, err := root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(temp)
	_, writeErr := f.Write(b)
	err = errors.Join(writeErr, f.Sync(), f.Close())
	if err != nil {
		return err
	}
	if err := root.Rename(temp, "rule-evaluations/"+report.ID+".json"); err != nil {
		return err
	}
	d, err := root.Open("rule-evaluations")
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

// ListOfflineEvaluations returns at most 100 reports in lexical evaluation-ID order.
// Malformed visible reports and an oversized history fail explicitly.
func ListOfflineEvaluations(directory string) ([]OfflineReport, error) {
	return listOfflineEvaluations(context.Background(), directory)
}

func listOfflineEvaluations(ctx context.Context, directory string) ([]OfflineReport, error) {
	r, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	info, err := r.Lstat("rule-evaluations")
	if errors.Is(err, os.ErrNotExist) {
		return []OfflineReport{}, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("invalid evaluation directory")
	}
	d, err := r.Open("rule-evaluations")
	if err != nil {
		return nil, err
	}
	defer d.Close()
	names, err := d.Readdirnames(201)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(names) > 200 {
		return nil, fmt.Errorf("offline report directory entry limit exceeded")
	}
	sort.Strings(names)
	reports := []OfflineReport{}
	var totalBytes int64
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if strings.HasPrefix(name, ".") {
			continue
		}
		if !strings.HasSuffix(name, ".json") || len(name) != 37 {
			return nil, fmt.Errorf("malformed visible offline report %s", name)
		}
		if _, err := hex.DecodeString(strings.TrimSuffix(name, ".json")); err != nil {
			return nil, err
		}
		if len(reports) >= 100 {
			return nil, fmt.Errorf("offline report history limit exceeded: 100")
		}
		path := filepath.Join("rule-evaluations", name)
		info, err := r.Lstat(path)
		if err != nil {
			return nil, err
		}
		if info.Size() > 1<<20 {
			return nil, fmt.Errorf("offline report exceeds 1 MiB")
		}
		b, _, err := offlineMetadata(ctx, r, path)
		if err != nil {
			return nil, err
		}
		totalBytes += int64(len(b))
		if len(b) > 1<<20 || totalBytes > 16<<20 {
			return nil, fmt.Errorf("offline report history byte limit exceeded")
		}
		var report OfflineReport
		decoder := json.NewDecoder(strings.NewReader(string(b)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&report); err != nil {
			return nil, err
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF || report.Version != 1 || report.ID+".json" != name || report.RunID == "" {
			return nil, fmt.Errorf("invalid offline report %s", name)
		}
		if err := offlineValidateReport(report); err != nil {
			return nil, fmt.Errorf("report %s: %w", name, err)
		}
		switch report.Status {
		case "committing", "complete", "partial", "publish-failed":
		default:
			return nil, fmt.Errorf("invalid offline report status")
		}
		reports = append(reports, report)
	}
	return reports, nil
}

func offlineValidateReport(r OfflineReport) error {
	hexDigest := func(s string) bool { b, err := hex.DecodeString(s); return err == nil && len(b) == 32 }
	if r.ObservationPolicyDigest != "" && !hexDigest(r.ObservationPolicyDigest) {
		return fmt.Errorf("invalid observation policy digest")
	}
	limits, err := normalizeOfflineLimits(r.Limits)
	if err != nil || limits != r.Limits || !hexDigest(r.PackDigest) || !hexDigest(r.ConfigDigest) || !hexDigest(r.InputCanonicalDigest) || r.CommittedAlerts < 0 || r.CommittedAlerts > r.PlannedAlerts || r.PlannedAlerts > r.Limits.Alerts || r.Elapsed < 0 || len(r.Rules) < 1 || len(r.Rules) > 64 || len(r.Types) > 4 || len(r.Files) < 2 || len(r.Files) > 6 {
		return fmt.Errorf("invalid report fields or limits")
	}
	if _, err := time.Parse(time.RFC3339Nano, r.StartedAt); err != nil {
		return err
	}
	for _, f := range r.Files {
		if !hexDigest(f.SHA256) || f.Bytes < 0 {
			return fmt.Errorf("invalid report file provenance")
		}
	}
	for _, s := range r.Rules {
		if !offlineID.MatchString(s.ID) || !hexDigest(s.Digest) || offlineRecord(s.Type) == nil || s.Matches < 0 || s.MissingGroups < 0 || s.Alerts < 0 {
			return fmt.Errorf("invalid rule report")
		}
	}
	return nil
}
