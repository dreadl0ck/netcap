//go:build coraza && http3

// Qualification exercises local fixtures only. Reports distinguish elapsed soak
// evidence from protocol integration coverage and production admission.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewalltransport"
	"github.com/dreadl0ck/netcap/internal/policy"
	"github.com/dreadl0ck/netcap/internal/waf"
	"github.com/quic-go/quic-go/http3"
)

const forbidden = "qualification-forbidden-marker"

type sample struct {
	Offered, Allowed, Denied, Errors, Dropped, FalseBlocks uint64
	Histogram                                              [32]uint64
	MaxMS                                                  float64
}

func (s *sample) observe(ms float64) {
	i := 0
	if ms > 1 {
		i = int(math.Ceil(math.Log2(ms)))
	}
	if i > 31 {
		i = 31
	}
	s.Histogram[i]++
	if ms > s.MaxMS {
		s.MaxMS = ms
	}
}

func (s sample) quantile(q float64) float64 {
	var total, count uint64
	for _, n := range s.Histogram {
		total += n
	}
	if total == 0 {
		return 0
	}
	for i, n := range s.Histogram {
		count += n
		if float64(count) >= math.Ceil(float64(total)*q) {
			return math.Min(math.Pow(2, float64(i)), s.MaxMS)
		}
	}
	return 0
}

type ledger struct {
	Requests          atomic.Uint64
	Bytes             atomic.Uint64
	ForbiddenRequests atomic.Uint64
	ForbiddenBytes    atomic.Uint64
	ForbiddenEffects  atomic.Uint64
}

// The ledger reads origin payloads without consulting firewall decisions.
func (l *ledger) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(io.LimitReader(r.Body, 65537))
	if err != nil || len(b) > 65536 {
		http.Error(w, "fixture limit", 413)
		return
	}
	l.Requests.Add(1)
	l.Bytes.Add(uint64(len(b)))
	if bytes.Contains(b, []byte(forbidden)) || bytes.Contains(b, []byte("<script>alert(1)</script>")) {
		l.ForbiddenRequests.Add(1)
		l.ForbiddenBytes.Add(uint64(len(b)))
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"fixture":"ok"}`)
}

type profile struct {
	lifecycle         sync.RWMutex
	Protocol          int
	CertificateSHA256 string
	OriginURL         string
	Stateful          bool
	StatePeak         policy.StateStats
	CustomRequest     func(workflow) (int, int, error)
	Fixture           string
	Name              string
	Rules             int
	CRS               bool
	Client            *http.Client
	URL               string
	FW                *waf.Firewall
	Policy            *policy.Compiled
	Ledger            *ledger
	Down              *atomic.Bool
	mu                sync.Mutex
	Stats             sample
	Failures          []requestFailure
	Close             func()
}

func compile(rules int, generation int) (*policy.Compiled, error) {
	return compileState(rules, generation, false)
}

func compileState(rules int, generation int, stateful bool) (*policy.Compiled, error) {
	b := policy.Bundle{Version: "v1", ID: fmt.Sprintf("qualification-%d-%d", rules, generation), Mode: "enforce", Default: "allow"}
	// Zero means zero filler rules; the safety rule is always present.
	for i := 0; i < rules; i++ {
		b.Rules = append(b.Rules, policy.Rule{ID: fmt.Sprintf("filler-%d", i), Phase: "request", Expression: fmt.Sprintf(`Path == "/unused/%d"`, i), Action: "deny", Status: 403})
	}
	b.Rules = append(b.Rules, policy.Rule{ID: "deny-marker", Phase: "request", Expression: `Body contains "` + forbidden + `"`, Action: "deny", Status: 403})
	if stateful {
		b.Rules = append(b.Rules, policy.Rule{ID: "bounded-state-probe", Phase: "request", Expression: `Method == "POST"`, Action: "deny", Status: 429, Threshold: &policy.Threshold{Mode: "sliding", Count: 1000, Window: "1s", GroupBy: "Path"}})
	}
	return policy.Compile(b)
}

func newProfile(ctx context.Context, rules int, crs bool, proto int) (*profile, error) {
	p := &profile{Rules: rules, CRS: crs, Ledger: &ledger{}, Down: &atomic.Bool{}, Protocol: proto}
	tlsConfig, certHash, err := fixtureTLS()
	if err != nil {
		return nil, err
	}
	p.CertificateSHA256 = certHash
	p.Name = fmt.Sprintf("h%d-%s-%d-filler", proto, map[bool]string{true: "crs", false: "native"}[crs], rules)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.Down.Load() {
			http.Error(w, "owned dependency unavailable", 503)
			return
		}
		p.Ledger.ServeHTTP(w, r)
	}))
	p.OriginURL = origin.URL
	policy, err := compile(rules, 0)
	if err != nil {
		origin.Close()
		return nil, err
	}
	p.Policy = policy
	cfg := waf.Config{Version: "netcap-firewall/v1", Listen: "127.0.0.1:8080", AdminListen: "127.0.0.1:9090", Upstream: origin.URL, MaxBodyBytes: 65536, MaxResponseBytes: 65536, MaxBufferedBytes: 8 << 20, MaxConcurrent: 32, BodyTimeout: "2s", CorazaCRS: crs}
	if crs {
		cfg.CRSTargetExclusions = []waf.CRSTargetExclusion{{Path: "/api/account", Method: "POST", Argument: "password", RuleID: 942100}}
	}
	p.FW, err = waf.New(cfg, policy)
	if err != nil {
		origin.Close()
		return nil, err
	}
	if proto != 3 {
		s := httptest.NewUnstartedServer(p.FW)
		s.TLS = tlsConfig
		s.EnableHTTP2 = proto == 2
		s.StartTLS()
		p.Client, p.URL = s.Client(), s.URL
		p.Client.Timeout = 3 * time.Second
		p.Close = func() { s.Close(); _ = p.FW.Close(); origin.Close() }
		return p, nil
	}
	cert := httptest.NewUnstartedServer(http.NotFoundHandler())
	cert.TLS = tlsConfig
	cert.StartTLS()
	roots := x509.NewCertPool()
	roots.AddCert(cert.Certificate())
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		cert.Close()
		_ = p.FW.Close()
		origin.Close()
		return nil, err
	}
	local, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		done <- firewalltransport.ServeHTTP3(local, udp, firewalltransport.HTTP3Config{TLS: cert.TLS, MaxConnections: 32, MaxStreams: 32, IdleTimeout: 5 * time.Second, ShutdownTimeout: 3 * time.Second}, p.FW)
	}()
	transport := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
	p.Client = &http.Client{Transport: transport, Timeout: 3 * time.Second}
	p.URL = "https://" + udp.LocalAddr().String()
	p.Close = func() {
		_ = transport.Close()
		cancel()
		<-done
		_ = udp.Close()
		cert.Close()
		_ = p.FW.Close()
		origin.Close()
	}
	return p, nil
}

type workflow struct{ Name, Path, ContentType, Body string }

// Password calibration follows the baseline 942100 false positive. Other
// held-out cases and attack controls are evaluated without further tuning.
var training = []workflow{
	{"invoice", "/api/invoices", "application/json", `{"invoice":"SYN-2026-001","currency":"EUR","total":125.50}`},
	{"search", "/search?q=quarterly+report", "application/x-www-form-urlencoded", "department=finance&quarter=Q4"},
	{"unicode", "/api/customers", "application/json", `{"name":"Synthetic café 東京","address":"Teststraat 42"}`},
	{"checkout", "/api/orders", "application/json", `{"sku":"fixture-42","quantity":2,"coupon":"AUTUMN"}`},
	{"password-calibration", "/api/account", "application/x-www-form-urlencoded", "password=Test%21%40%23%242026&confirm=yes"},
}
var withheld = []workflow{
	{"apostrophe", "/api/customers", "application/json", `{"name":"O'Reilly synthetic","note":"Meeting at 10:30"}`},
	{"math", "/api/report", "application/json", `{"formula":"revenue < 1000 and margin > 20","period":"2026-Q4"}`},
	{"password-held-out", "/api/account", "application/x-www-form-urlencoded", "password=Other%21%40%23%242027&confirm=yes"},
	{"comment", "/api/comments", "application/json", `{"text":"Please select the union plan for the synthetic team."}`},
}

func (p *profile) request(w workflow) (int, int, error) {
	p.lifecycle.RLock()
	defer p.lifecycle.RUnlock()
	return p.requestUnlocked(w)
}

func (p *profile) requestUnlocked(w workflow) (int, int, error) {
	if p.CustomRequest != nil {
		return p.CustomRequest(w)
	}
	r, err := http.NewRequest("POST", p.URL+w.Path, strings.NewReader(w.Body))
	if err != nil {
		return 0, 0, err
	}
	r.Header.Set("Content-Type", w.ContentType)
	r.Header.Set("User-Agent", "NetcapQualification/1.0")
	r.Header.Set("Accept", "application/json")
	var stage atomic.Int32
	r = r.WithContext(httptrace.WithClientTrace(r.Context(), &httptrace.ClientTrace{
		ConnectStart:         func(_, _ string) { stage.Store(1) },
		TLSHandshakeDone:     func(tls.ConnectionState, error) { stage.Store(2) },
		GotConn:              func(httptrace.GotConnInfo) { stage.Store(3) },
		WroteRequest:         func(httptrace.WroteRequestInfo) { stage.Store(4) },
		GotFirstResponseByte: func() { stage.Store(5) },
	}))
	resp, err := p.Client.Do(r)
	if err != nil {
		return 0, 0, wireStage("http-"+[]string{"start", "connect", "tls", "connection", "request-written", "response-started"}[stage.Load()], err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if len(body) > 65536 {
		err = errors.New("response fixture exceeded bound")
	}
	if resp.StatusCode == 200 && string(body) != `{"fixture":"ok"}` {
		err = errors.New("origin response mismatch")
	}
	return resp.StatusCode, resp.ProtoMajor, err
}

func corpus(profiles []*profile) ([]map[string]any, error) {
	var rows []map[string]any
	var failures int
	for _, p := range profiles {
		for group, cases := range map[string][]workflow{"training": training, "withheld": withheld} {
			for _, w := range cases {
				before := p.Ledger.Requests.Load()
				status, proto, err := p.request(w)
				hash := sha256.Sum256([]byte(w.Body))
				rows = append(rows, map[string]any{"profile": p.Name, "split": group, "case": w.Name, "path": w.Path, "payload_sha256": fmt.Sprintf("%x", hash), "origin_request_delta": p.Ledger.Requests.Load() - before, "status": status, "protocol": proto, "error": fmt.Sprint(err)})
				if err != nil || status != 200 || proto != p.Protocol || p.Ledger.Requests.Load()-before != 1 {
					failures++
				}
			}
		}
		attacks := []workflow{{"native-attack", "/api/invoices", "application/json", `{"value":"` + forbidden + `"}`}}
		if p.CRS {
			attacks = append(attacks, workflow{"xss", "/api/comments", "application/x-www-form-urlencoded", "comment=<script>alert(1)</script>"})
			attacks = append(attacks,
				workflow{"xss-password", "/api/account", "application/x-www-form-urlencoded", "password=<script>alert(1)</script>"},
				workflow{"sqli-other-field", "/api/account", "application/x-www-form-urlencoded", "comment=Test%21%40%23%242026"},
				workflow{"sqli-other-route", "/api/orders", "application/x-www-form-urlencoded", "password=Test%21%40%23%242026"})
		}
		for _, w := range attacks {
			before := p.Ledger.Requests.Load()
			status, proto, err := p.request(w)
			rows = append(rows, map[string]any{"profile": p.Name, "split": "attack-control", "case": w.Name, "path": w.Path, "origin_request_delta": p.Ledger.Requests.Load() - before, "status": status, "protocol": proto, "error": fmt.Sprint(err)})
			if err != nil || status != 403 || proto != p.Protocol || p.Ledger.Requests.Load() != before {
				failures++
			}
		}
	}
	if failures != 0 {
		return rows, fmt.Errorf("corpus has %d failures", failures)
	}
	return rows, nil
}

func checkLedger(l *ledger) error {
	if l.ForbiddenRequests.Load() != 0 || l.ForbiddenBytes.Load() != 0 || l.ForbiddenEffects.Load() != 0 {
		return errors.New("independent origin ledger detected forbidden payload")
	}
	return nil
}

func negativeControl() error {
	l := &ledger{}
	s := httptest.NewServer(l)
	defer s.Close()
	r, err := http.Post(s.URL, "text/plain", strings.NewReader(forbidden))
	if err != nil {
		return err
	}
	_ = r.Body.Close()
	if checkLedger(l) == nil {
		return errors.New("leak negative control did not fail")
	}
	return nil
}

type resources struct {
	HeapBytes       uint64
	GoReservedBytes uint64
	Goroutines      int
	RSSBytes        int64
	FDs             int
	DiskBytes       int64
}

func resourceSnapshot() resources {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	r := resources{HeapBytes: m.HeapAlloc, GoReservedBytes: m.Sys, Goroutines: runtime.NumGoroutine(), RSSBytes: -1, FDs: -1}
	// Missing native samples are explicit (-1); macOS uses PID-scoped ps/lsof.
	if b, err := os.ReadFile("/proc/self/statm"); err == nil {
		var total, resident int64
		if _, err := fmt.Sscan(string(b), &total, &resident); err == nil {
			r.RSSBytes = resident * int64(os.Getpagesize())
		}
	}
	if entries, err := os.ReadDir("/proc/self/fd"); err == nil {
		r.FDs = len(entries)
	}
	if runtime.GOOS == "darwin" {
		if b, err := exec.Command("/bin/ps", "-o", "rss=", "-p", strconv.Itoa(os.Getpid())).Output(); err == nil {
			if kb, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil {
				r.RSSBytes = kb * 1024
			}
		}
		if entries, err := exec.Command("/usr/sbin/lsof", "-a", "-p", strconv.Itoa(os.Getpid()), "-Ff").Output(); err == nil {
			r.FDs = 0
			for _, line := range strings.Split(string(entries), "\n") {
				if len(line) > 1 && line[0] == 'f' && line[1] >= '0' && line[1] <= '9' {
					r.FDs++
				}
			}
		}
	}
	return r
}

func atomicJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

type options struct {
	Duration      time.Duration
	Rate          int
	Workers       int
	Output        string
	Quick         bool
	CorpusOnly    bool
	Rules         string
	FaultEvery    time.Duration
	MaxP99        time.Duration
	MinGoodput    float64
	MaxHeap       uint64
	InjectLeak    bool
	Mixed         bool
	MaxRSS        int64
	MaxFDs        int
	MaxGoroutines int
	MaxDisk       int64
}

func run(ctx context.Context, o options) (err error) {
	scratch, e := os.MkdirTemp(o.Output, "scratch-")
	if e != nil {
		return e
	}
	previousTemp := os.Getenv("TMPDIR")
	_ = os.Setenv("TMPDIR", scratch)
	defer func() { _ = os.Setenv("TMPDIR", previousTemp); _ = os.RemoveAll(scratch) }()
	snapshot := func() resources { r := resourceSnapshot(); r.DiskBytes = diskBytes(scratch); return r }
	idle := snapshot()
	if err = negativeControl(); err != nil {
		return err
	}
	started := time.Now()
	var profiles []*profile
	closed := false
	closeProfiles := func() {
		if !closed {
			for _, p := range profiles {
				p.Close()
			}
			closed = true
		}
	}
	defer func() {
		closeProfiles()
	}()
	seenRules := map[int]bool{}
	for _, text := range strings.Split(o.Rules, ",") {
		n, parseErr := strconv.Atoi(text)
		if parseErr != nil || (n != 0 && n != 10 && n != 100 && n != 1000) || seenRules[n] {
			return errors.New("rules must be comma-separated 0,10,100,1000")
		}
		seenRules[n] = true
		for _, crs := range []bool{false, true} {
			for _, proto := range []int{1, 2, 3} {
				p, err := newProfile(ctx, n, crs, proto)
				if err != nil {
					return err
				}
				profiles = append(profiles, p)
			}
		}
	}
	var rows []map[string]any
	corpusErr := ctx.Err()
	if corpusErr == nil {
		rows, corpusErr = corpus(profiles)
	}
	if o.InjectLeak {
		// Bypass the firewall once: the independent origin observer must fail the run.
		resp, e := http.Post(profiles[0].OriginURL, "text/plain", strings.NewReader(forbidden))
		if e != nil {
			return e
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("negative-control origin failed: %d", resp.StatusCode)
		}
		_ = atomicJSON(filepath.Join(o.Output, "negative-control.json"), map[string]any{"result": "detected", "forbidden_bytes": profiles[0].Ledger.ForbiddenBytes.Load()})
		return checkLedger(profiles[0].Ledger)
	}
	falseBlocks := 0
	for _, row := range rows {
		if row["split"] != "attack-control" && row["status"] == 403 {
			falseBlocks++
		}
	}
	corpusState := "pass"
	if corpusErr != nil {
		corpusState = "fail"
	}
	if err = atomicJSON(filepath.Join(o.Output, "falsepositives.json"), map[string]any{"result": corpusState, "owned_synthetic_cases": rows, "critical_false_blocks": falseBlocks, "critical_false_blocks_required": 0, "policy_tuning": "one target only: CRS 942100 ARGS:password on POST /api/account; baseline withheld password promoted to calibration; XSS/other-field/other-route/native controls retained", "ftw_reviewed_corpus": "separate -ftw-only evidence"}); err != nil {
		return err
	}
	if o.CorpusOnly {
		return corpusErr
	}
	if corpusErr != nil {
		log.Printf("false-positive qualification failed (preserved separately): %v", corpusErr)
	}
	if o.Mixed {
		stateful, e := newProfile(ctx, 0, false, 1)
		if e != nil {
			return e
		}
		profiles = append(profiles, stateful)
		stateful.Name = "h1-native-stateful"
		stateful.Stateful = true
		compiled, e := compileState(0, 0, true)
		if e != nil {
			return e
		}
		stateful.FW.SetPolicy(compiled)
	}
	httpCount := len(profiles)
	if o.Mixed {
		p, e := newDNSProfile(ctx)
		if e != nil {
			return e
		}
		profiles = append(profiles, p)
		for _, protocol := range []string{"redis", "postgres", "mysql", "smtp", "modbus", "dnp3"} {
			p, e := newTCPProfile(ctx, protocol)
			if e != nil {
				return e
			}
			profiles = append(profiles, p)
		}
		for _, protocol := range []string{"websocket", "grpc"} {
			p, e := newMessageProfile(ctx, protocol)
			if e != nil {
				return e
			}
			profiles = append(profiles, p)
		}
	}
	baseline := snapshot()
	var latest atomic.Value
	latest.Store(baseline)
	samplerCtx, stopSampler := context.WithCancel(ctx)
	samplerDone := make(chan struct{})
	go func() {
		defer close(samplerDone)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-samplerCtx.Done():
				return
			case <-ticker.C:
				latest.Store(snapshot())
			}
		}
	}()
	defer func() { stopSampler(); <-samplerDone }()
	start := time.Now().Add(100 * time.Millisecond)
	jobs := make(chan func(), o.Workers)
	var wg sync.WaitGroup
	for i := 0; i < o.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				job()
			}
		}()
	}
	var faults []map[string]any
	faultCount := 0
	nextFault := start.Add(o.FaultEvery)
	nextSnapshot := start
	var resourcePeak resources
	var recovery resources
	var offered uint64
	var activeFault atomic.Int64
	state := "running"
	report := func() error {
		elapsed := math.Max(0, math.Min(time.Since(start).Seconds(), o.Duration.Seconds()))
		stats := map[string]any{}
		for _, p := range profiles {
			p.mu.Lock()
			s := p.Stats
			failures := append([]requestFailure(nil), p.Failures...)
			p.mu.Unlock()
			stateUsage := policy.StateStats{}
			if p.FW != nil {
				stateUsage = p.FW.Policy().StateStats()
			}
			if stateUsage.Entries > p.StatePeak.Entries {
				p.StatePeak.Entries = stateUsage.Entries
			}
			if stateUsage.Groups > p.StatePeak.Groups {
				p.StatePeak.Groups = stateUsage.Groups
			}
			if stateUsage.AccountedBytes > p.StatePeak.AccountedBytes {
				p.StatePeak.AccountedBytes = stateUsage.AccountedBytes
			}
			stats[p.Name] = map[string]any{"counts": s, "p95_upper_ms": s.quantile(.95), "p99_upper_ms": s.quantile(.99), "accepted_goodput_rps": float64(s.Allowed) / math.Max(elapsed, .001), "origin_requests": p.Ledger.Requests.Load(), "origin_bytes": p.Ledger.Bytes.Load(), "forbidden_origin_requests": p.Ledger.ForbiddenRequests.Load(), "forbidden_origin_bytes": p.Ledger.ForbiddenBytes.Load(), "forbidden_side_effects": p.Ledger.ForbiddenEffects.Load(), "fixture": p.Fixture, "filler_rules": p.Rules, "safety_rules": 1}
			row := stats[p.Name].(map[string]any)
			row["first_failures"], row["failure_history_limit"] = failures, 16
			row["evaluator_state_current"], row["evaluator_state_peak"], row["stateful_probe"] = stateUsage, p.StatePeak, p.Stateful
			if p.Stateful {
				row["safety_rules"] = 2
			}
		}
		return atomicJSON(filepath.Join(o.Output, "progress.json"), map[string]any{
			"load_state": state, "qualification_state": "incomplete", "false_positive_error": fmt.Sprint(corpusErr),
			"pid": os.Getpid(), "started": started.UTC(), "updated": time.Now().UTC(),
			"requested_seconds": o.Duration.Seconds(), "actual_load_seconds": elapsed,
			"actual_wall_seconds": time.Since(start).Seconds(), "resource_sampling_seconds": 5, "load_error": fmt.Sprint(err),
			"soak_24h_pass": state == "pass" && corpusErr == nil && o.Mixed && o.Duration >= 24*time.Hour && elapsed >= 86400,
			"profiles":      stats, "resources_idle": idle, "resources_baseline": baseline, "resources_current": latest.Load().(resources), "resources_peak": resourcePeak, "resources_recovery": recovery,
			"resource_scope": "whole runner plus in-process WAF and origins; no per-profile native RSS attribution",
			"faults":         faults, "fault_count": faultCount, "fault_history_limit": 256, "thresholds": o,
			"negative_control":   "deliberate direct-origin leak detected",
			"latency":            "scheduled arrival to completion; log2 millisecond histogram upper bounds; generator drops fail",
			"scope":              "loopback fixtures; no hardware or production capacity claim",
			"mixed_wire_enabled": o.Mixed,
			"pending": []string{"24h actual run unless soak_24h_pass=true", "mixed wire profiles require -mixed; scripted peers are not vendor servers",
				"FTW is separate -ftw-only evidence; no full corpus coverage", "Docker edge TLS/NAT/LB/CNI packet-loss",
				"OS process restart and external state dependency recovery", "per-profile native RSS/FD/disk/state attribution"},
		})
	}
	drained := false
	drain := func() {
		if !drained {
			close(jobs)
			wg.Wait()
			drained = true
		}
	}
	defer func() {
		drain()
		closeProfiles()
		runtime.GC()
		recovery = snapshot()
		if err != nil {
			state = "failed"
		} else {
			state = "pass"
		}
		if e := report(); err == nil {
			err = e
		}
	}()
	count := uint64(o.Duration.Seconds() * float64(o.Rate))
	for i := uint64(0); i < count; i++ {
		planned := start.Add(time.Duration(float64(i) * float64(time.Second) / float64(o.Rate)))
		timer := time.NewTimer(time.Until(planned))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		p := profiles[i%uint64(len(profiles))]
		p.mu.Lock()
		p.Stats.Offered++
		p.mu.Unlock()
		attack := (i/uint64(len(profiles)))%5 == 0
		w := training[(i/uint64(len(profiles))/5)%uint64(len(training))]
		if attack {
			w = workflow{"attack", "/api/invoices", "application/json", `{"value":"` + forbidden + `"}`}
		}
		job := func() {
			began := time.Now()
			faultAtStart := activeFault.Load()
			status, _, requestErr := p.request(w)
			p.mu.Lock()
			defer p.mu.Unlock()
			p.Stats.observe(float64(time.Since(planned)) / float64(time.Millisecond))
			switch {
			case requestErr != nil:
				p.Stats.Errors++
			case attack && status == 403:
				p.Stats.Denied++
			case !attack && status == 200:
				p.Stats.Allowed++
			case !attack && status == 403:
				p.Stats.FalseBlocks++
			default:
				p.Stats.Errors++
			}
			if requestErr != nil || attack && status != 403 || !attack && status != 200 {
				failure := describeFailure(requestErr)
				failure.Sequence, failure.Attack, failure.Status = i, attack, status
				failure.ElapsedSeconds = time.Since(start).Seconds()
				failure.ScheduleDelayMS = float64(began.Sub(planned)) / float64(time.Millisecond)
				failure.RequestMS = float64(time.Since(began)) / float64(time.Millisecond)
				failure.FaultAtStart, failure.FaultAtEnd = faultAtStart, activeFault.Load()
				if len(p.Failures) < 16 {
					p.Failures = append(p.Failures, failure)
					log.Printf("request failure profile=%s detail=%+v", p.Name, failure)
				}
			}
		}
		select {
		case jobs <- job:
		default:
			p.mu.Lock()
			p.Stats.Dropped++
			p.mu.Unlock()
		}
		offered++
		if time.Now().After(nextFault) {
			p := profiles[faultCount%httpCount]
			activeFault.Store(int64(faultCount + 1))
			fault, e := p.exerciseFault(ctx, faultCount+1)
			activeFault.Store(0)
			faults = append(faults, fault)
			if len(faults) > 256 {
				faults = faults[len(faults)-256:]
			}
			if e != nil {
				return e
			}
			faultCount++
			nextFault = nextFault.Add(o.FaultEvery)
		}
		if time.Now().After(nextSnapshot) {
			r := latest.Load().(resources)
			if r.HeapBytes > resourcePeak.HeapBytes {
				resourcePeak.HeapBytes = r.HeapBytes
			}
			if r.RSSBytes > resourcePeak.RSSBytes {
				resourcePeak.RSSBytes = r.RSSBytes
			}
			if r.FDs > resourcePeak.FDs {
				resourcePeak.FDs = r.FDs
			}
			if r.Goroutines > resourcePeak.Goroutines {
				resourcePeak.Goroutines = r.Goroutines
			}
			if r.GoReservedBytes > resourcePeak.GoReservedBytes {
				resourcePeak.GoReservedBytes = r.GoReservedBytes
			}
			if r.DiskBytes > resourcePeak.DiskBytes {
				resourcePeak.DiskBytes = r.DiskBytes
			}
			if r.HeapBytes > o.MaxHeap {
				return fmt.Errorf("heap limit exceeded: %d", r.HeapBytes)
			}
			if (o.MaxRSS > 0 && r.RSSBytes > o.MaxRSS) || (o.MaxFDs > 0 && r.FDs > o.MaxFDs) || (o.MaxGoroutines > 0 && r.Goroutines > o.MaxGoroutines) || (o.MaxDisk > 0 && r.DiskBytes > o.MaxDisk) {
				return fmt.Errorf("resource fail budget exceeded: %+v", r)
			}
			if err = report(); err != nil {
				return err
			}
			for _, p := range profiles {
				if err = checkLedger(p.Ledger); err != nil {
					return err
				}
				p.mu.Lock()
				s := p.Stats
				p.mu.Unlock()
				if s.Errors > 0 || s.Dropped > 0 || s.FalseBlocks > 0 {
					return fmt.Errorf("zero-error live fail budget exceeded: %s %+v", p.Name, s)
				}
			}
			nextSnapshot = time.Now().Add(5 * time.Second)
		}
	}
	timer := time.NewTimer(time.Until(start.Add(o.Duration)))
	select {
	case <-ctx.Done():
		timer.Stop()
		return ctx.Err()
	case <-timer.C:
	}
	// Drain before the acceptance decision, without retaining request samples.
	drain()
	if o.Mixed {
		// Let the exercised one-second local state windows expire before maintenance.
		time.Sleep(1100 * time.Millisecond)
		for _, p := range profiles {
			if p.Stateful {
				usage, e := p.FW.Policy().Maintain()
				if e != nil {
					return e
				}
				if usage.Entries != 0 || usage.Groups != 0 {
					return fmt.Errorf("evaluator state did not recover: %+v", usage)
				}
			}
		}
	}
	for _, p := range profiles {
		if err = checkLedger(p.Ledger); err != nil {
			return err
		}
		s := p.Stats
		if s.Offered == 0 || s.Allowed == 0 || s.Denied == 0 || s.Dropped != 0 || s.Errors != 0 || s.FalseBlocks != 0 || s.quantile(.99) > float64(o.MaxP99)/float64(time.Millisecond) || float64(s.Allowed+s.Denied)/float64(s.Offered) < o.MinGoodput {
			return fmt.Errorf("profile acceptance failed: %s: %+v", p.Name, s)
		}
		if p.FW != nil && p.FW.BodyCapabilities().BufferedBytes != 0 {
			return fmt.Errorf("buffer state did not recover: %s", p.Name)
		}
	}
	log.Printf("completed %d scheduled requests over %s", offered, o.Duration)
	return nil
}

func main() {
	var o options
	var ftwOnly bool
	flag.BoolVar(&ftwOnly, "ftw-only", false, "fetch immutable Apache-licensed reviewed FTW subset and exercise owned fixtures only")
	flag.DurationVar(&o.Duration, "duration", 24*time.Hour, "actual offered-load duration (maximum 7 days)")
	flag.IntVar(&o.Rate, "rate", 50, "aggregate open-loop requests/second, 1..1000")
	flag.IntVar(&o.Workers, "workers", 32, "bounded generator workers, 1..128")
	flag.StringVar(&o.Output, "output", "", "existing evidence directory outside git")
	flag.BoolVar(&o.Quick, "quick", false, "bound duration to <=60 seconds")
	flag.BoolVar(&o.CorpusOnly, "corpus-only", false, "run owned benign and attack corpus; false blocks return nonzero")
	flag.BoolVar(&o.InjectLeak, "inject-leak", false, "independent harness negative control: deliberately leak to the owned observer and exit nonzero")
	flag.BoolVar(&o.Mixed, "mixed", false, "include owned real-wire DNS/Redis/Postgres/MySQL/SMTP/Modbus/DNP3 profiles in the open-loop schedule")
	flag.StringVar(&o.Rules, "rules", "0,10,100,1000", "filler rule counts, plus one safety rule")
	flag.DurationVar(&o.FaultEvery, "fault-every", time.Minute, "owned dependency outage and policy reload interval, >=1s")
	flag.DurationVar(&o.MaxP99, "max-p99", 2*time.Second, "schedule-to-completion histogram p99 limit")
	flag.Float64Var(&o.MinGoodput, "min-completion", 1, "minimum successful allow or deny fraction")
	flag.Uint64Var(&o.MaxHeap, "max-heap", 1<<30, "whole-process Go heap ceiling bytes")
	flag.Int64Var(&o.MaxRSS, "max-rss", 2<<30, "whole-process RSS ceiling bytes; unsupported sampling is explicit")
	flag.IntVar(&o.MaxFDs, "max-fds", 4096, "whole-process descriptor ceiling")
	flag.IntVar(&o.MaxGoroutines, "max-goroutines", 4096, "whole-process goroutine ceiling")
	flag.Int64Var(&o.MaxDisk, "max-disk", 64<<20, "owned scratch highwater ceiling bytes")
	flag.Parse()
	if o.Quick && o.Duration == 24*time.Hour {
		o.Duration = 10 * time.Second
	}
	if o.Duration <= 0 || o.Duration > 7*24*time.Hour || (o.Quick && o.Duration > time.Minute) || o.Rate < 1 || o.Rate > 1000 || o.Workers < 1 || o.Workers > 128 || o.FaultEvery < time.Second || o.MaxP99 <= 0 || o.MinGoodput <= 0 || o.MinGoodput > 1 || o.Output == "" {
		log.Fatal("invalid bounds; see -help")
	}
	if stat, err := os.Stat(o.Output); err != nil || !stat.IsDir() {
		log.Fatal("output must be an existing directory")
	}
	// Keep evidence outside every git worktree, including ignored directories.
	abs, err := filepath.EvalSymlinks(o.Output)
	if err == nil {
		abs, err = filepath.Abs(abs)
	}
	if err != nil {
		log.Fatal(err)
	}
	for p := abs; ; p = filepath.Dir(p) {
		if _, e := os.Stat(filepath.Join(p, ".git")); e == nil {
			log.Fatal("evidence must be outside git")
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	o.Output = abs
	entries, _ := os.ReadDir(abs)
	if len(entries) != 0 {
		log.Fatal("use an empty evidence directory; reports must not overwrite another run")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if ftwOnly {
		if err := runFTW(ctx, o.Output); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := run(ctx, o); err != nil {
		log.Fatal(err)
	}
}
