package software

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/internal/dbs"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/enrichment"
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/internal/webtech"
	"github.com/dreadl0ck/netcap/types"
)

func writeWebtechDiagnostics() {
	status, counts := WebtechDiagnostics()
	softwareLog.Info("passive webtech diagnostics", zap.Any("catalogue", status), zap.Any("body_states", counts))
	if decoderconfig.Instance == nil || decoderconfig.Instance.Out == "" {
		return
	}
	b, err := json.MarshalIndent(map[string]any{"catalogue": status, "body_states": counts, "counter_scope": "capture", "negative_conclusion": false}, "", "  ")
	if err == nil {
		err = os.WriteFile(filepath.Join(decoderconfig.Instance.Out, "webtech-status.json"), append(b, '\n'), 0600)
	}
	if err != nil {
		softwareLog.Warn("cannot write webtech diagnostics", zap.Error(err))
	}
}

var webtechRuntime struct {
	initMu sync.Mutex
	engine atomic.Pointer[webtech.Engine]
	status webtech.Status
	sync.Mutex
	states map[string]uint64
	claims int
}

func webtechEngine() *webtech.Engine {
	if e := webtechRuntime.engine.Load(); e != nil {
		return e
	}
	InitializeWebtech()
	return webtechRuntime.engine.Load()
}

// InitializeWebtech snapshots optional data before capture workers start.
func InitializeWebtech() webtech.Status {
	trust, err := dbs.CommunitySigningRoot()
	if err != nil {
		softwareLog.Warn("webtech signing root unavailable", zap.Error(err))
	}
	return InitializeWebtechWith(enrichment.Root(resolvers.ConfigRootPath), trust, time.Now())
}

func InitializeWebtechWith(root string, trust ed25519.PublicKey, now time.Time) webtech.Status {
	webtechRuntime.initMu.Lock()
	defer webtechRuntime.initMu.Unlock()
	e := webtech.Builtin()
	status := webtech.Status{State: "unverified-builtins", Rules: 2}
	var members map[string][]byte
	var err error
	if len(trust) != ed25519.PublicKeySize {
		err = fmt.Errorf("invalid enrichment trust root")
	} else {
		members, err = enrichment.Open(root, trust, now)
	}
	if err == nil {
		data, ok := members[webtech.FileName]
		if !ok {
			err = fmt.Errorf("optional %s missing", webtech.FileName)
		} else {
			var parsed *webtech.Engine
			parsed, err = webtech.Parse(data)
			if err == nil {
				e = parsed
				status = webtech.Status{State: "external", Rules: e.RuleCount(), SHA256: fmt.Sprintf("%x", sha256.Sum256(data))}
			}
		}
	}
	if err != nil {
		softwareLog.Warn("optional webtech snapshot unavailable; using first-party builtins", zap.Error(err))
	}
	webtechRuntime.Lock()
	webtechRuntime.status = status
	webtechRuntime.states = map[string]uint64{}
	webtechRuntime.claims = 0
	webtechRuntime.Unlock()
	webtechRuntime.engine.Store(e)
	softwareLog.Info("passive webtech catalogue", zap.Any("status", status))
	return status
}

// WebtechDiagnostics contains counts and catalogue identity, never body/cookies.
func WebtechDiagnostics() (webtech.Status, map[string]uint64) {
	webtechEngine()
	webtechRuntime.Lock()
	defer webtechRuntime.Unlock()
	counts := map[string]uint64{}
	for k, v := range webtechRuntime.states {
		counts[k] = v
	}
	return webtechRuntime.status, counts
}

// ObserveWebtech is called on a paired response before payload disposal. No raw
// HTML, header value, cookie, URL query or external dependency is retained.
func ObserveWebtech(o webtech.Observation, body io.Reader, encoding, authority, flow, cid string, ts int64) webtech.Report {
	report := webtechEngine().ObserveReader(o, body, encoding)
	webtechRuntime.Lock()
	webtechRuntime.states[report.BodyState]++
	webtechRuntime.Unlock()
	if authority == "" || len(authority) > 256 || strings.ContainsAny(authority, "\r\n\x00") {
		return report
	}
	for _, m := range report.Matches {
		webtechRuntime.Lock()
		if webtechRuntime.claims >= 4096 {
			webtechRuntime.states["software-record-limit"]++
			webtechRuntime.Unlock()
			continue
		}
		webtechRuntime.claims++
		webtechRuntime.Unlock()
		s := RenderWebtech(m, authority, flow, cid, ts)
		WriteSoftware([]*AtomicSoftware{{Software: s}}, nil)
	}
	return report
}

func RenderWebtech(m webtech.Result, authority, flow, cid string, ts int64) *types.Software {
	s := &types.Software{Timestamp: ts, Product: m.Product, Version: m.Version, SourceName: "Passive WebTech", SourceData: m.Product, Service: "HTTP", DetectionMethod: "webtech_advertisement", ConfidenceLevel: "low", ObservationRole: "origin", BehaviorProfile: "server", VulnerabilityAssessment: "advertised-origin-only", Flows: []string{flow}, Notes: fmt.Sprintf("rule=%s; precision=%s; scope=origin-transaction; authority=%s; transaction=%d", m.ID, m.Precision, authority, ts)}
	if cid != "" {
		s.CommunityIDs = []string{cid}
	}
	s.InstanceCount = 1
	return s
}
