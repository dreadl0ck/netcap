package rules

import (
	"fmt"
	"reflect"
	"time"
)

type OfflineRequest struct {
	Directory string        `json:"directory"`
	Pack      *OfflinePack  `json:"pack"`
	Limits    OfflineLimits `json:"limits"`
}

// Zero selects the default. Positive overrides may only reduce the hard ceiling.
// Limits are bounded below JavaScript's exact-integer ceiling, including duration in nanoseconds.
type OfflineLimits struct {
	FrameBytes     int64         `json:"frameBytes"`
	Records        int64         `json:"records"`
	DecodedBytes   int64         `json:"decodedBytes"`
	SortBytes      int64         `json:"sortBytes"`
	StateBytes     int64         `json:"stateBytes"`
	GroupsPerRule  int64         `json:"groupsPerRule"`
	Groups         int64         `json:"groups"`
	PendingPerRule int64         `json:"pendingPerRule"`
	Pending        int64         `json:"pending"`
	Rules          int64         `json:"rules"`
	Alerts         int64         `json:"alerts"`
	AlertBytes     int64         `json:"alertBytes"`
	Duration       time.Duration `json:"duration"`
}

func DefaultOfflineLimits() OfflineLimits {
	return OfflineLimits{4 << 20, 100000, 256 << 20, 128 << 20, 64 << 20, 4096, 16384, 65536, 262144, 64, 10000, 32 << 20, 2 * time.Minute}
}

func normalizeOfflineLimits(in OfflineLimits) (OfflineLimits, error) {
	out := DefaultOfflineLimits()
	a, b := reflect.ValueOf(&out).Elem(), reflect.ValueOf(in)
	for i := 0; i < a.NumField(); i++ {
		n := b.Field(i).Int()
		if n < 0 || n > a.Field(i).Int() {
			return out, fmt.Errorf("offline limit %s must be positive and <=%d (zero selects default)", a.Type().Field(i).Name, a.Field(i).Int())
		}
		if n != 0 {
			a.Field(i).SetInt(n)
		}
	}
	return out, nil
}

type OfflineFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes,string"`
}

type OfflineTypeStats struct {
	Type           string `json:"type"`
	Records        int64  `json:"records,string"`
	CanonicalBytes int64  `json:"canonicalBytes,string"`
	Missing        bool   `json:"missing"`
	UnknownScopes  int64  `json:"unknownScopes,string"`
}

type OfflineRuleStats struct {
	ID            string `json:"id"`
	Type          string `json:"type"`
	Digest        string `json:"digest"`
	Enabled       bool   `json:"enabled"`
	Matches       int64  `json:"matches,string"`
	MissingGroups int64  `json:"missingGroups,string"`
	Alerts        int64  `json:"alerts,string"`
}

type OfflineReport struct {
	Version                 int                `json:"version"`
	ID                      string             `json:"id"`
	RunID                   string             `json:"runId"`
	Status                  string             `json:"status"`
	Error                   string             `json:"error,omitempty"`
	StartedAt               string             `json:"startedAt"`
	Elapsed                 time.Duration      `json:"elapsed,string"`
	PackDigest              string             `json:"packDigest"`
	ConfigDigest            string             `json:"configDigest"`
	ObservationPolicyDigest string             `json:"observationPolicyDigest,omitempty"`
	InputCanonicalDigest    string             `json:"inputCanonicalDigest"`
	Files                   []OfflineFile      `json:"files"`
	Types                   []OfflineTypeStats `json:"types"`
	Rules                   []OfflineRuleStats `json:"rules"`
	Limits                  OfflineLimits      `json:"limits"`
	Limitations             []string           `json:"limitations"`
	PlannedAlerts           int64              `json:"plannedAlerts,string"`
	CommittedAlerts         int64              `json:"committedAlerts,string"`
}

type OfflineContributor struct {
	File       string `json:"file"`
	Ordinal    uint64 `json:"ordinal,string"`
	SHA256     string `json:"sha256"`
	Timestamp  int64  `json:"timestamp,string"`
	FileSHA256 string `json:"fileSHA256,omitempty"`
}

// Integer groups retain their Go type without passing through a JSON number.
type offlineInteger struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type OfflineAlertMetadata struct {
	Version                 int                  `json:"version"`
	EventID                 string               `json:"eventId"`
	RunID                   string               `json:"runId"`
	RuleID                  string               `json:"ruleId"`
	RuleDigest              string               `json:"ruleDigest"`
	InputCanonicalDigest    string               `json:"inputCanonicalDigest"`
	ObservationPolicyDigest string               `json:"observationPolicyDigest,omitempty"`
	Group                   map[string]any       `json:"group"`
	Count                   int                  `json:"count"`
	First                   int64                `json:"first,string"`
	Last                    int64                `json:"last,string"`
	WindowNs                int64                `json:"windowNs,string"`
	Contributors            []OfflineContributor `json:"contributors"`
	ContributorsTruncated   bool                 `json:"contributorsTruncated"`
}
