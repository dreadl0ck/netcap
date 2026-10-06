package behavior

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const HealthFilename = "BehaviorHealth.json"

type CaptureHealth struct {
	Scope          Scope   `json:"scope"`
	Packets        uint64  `json:"packets"`
	QueueDrops     *uint64 `json:"queueDrops"`
	KernelDrops    *uint64 `json:"kernelDrops"`
	KernelReceived *uint64 `json:"kernelReceived"`
	StatsAt        int64   `json:"statsAt"`
	StatsError     string  `json:"statsError,omitempty"`
	Workers        int     `json:"workers"`
	Queued         int     `json:"queued"`
	QueueCapacity  int     `json:"queueCapacity"`
}

type DeliveryHealth struct {
	Acked    uint64 `json:"acked"`
	Rejected uint64 `json:"rejected"`
	Dropped  uint64 `json:"dropped"`
	Pending  int    `json:"pending"`
}

type Health struct {
	Schema            int             `json:"schema"`
	SampledAt         int64           `json:"sampledAt"`
	Active            bool            `json:"active"`
	Scopes            []Scope         `json:"scopes"`
	ScopesTruncated   bool            `json:"scopesTruncated"`
	Capture           *CaptureHealth  `json:"capture"`
	Delivery          *DeliveryHealth `json:"delivery"`
	DetectorError     string          `json:"detectorError,omitempty"`
	Observations      uint64          `json:"observations"`
	FactOverflow      uint64          `json:"factOverflow"`
	WindowOverflow    uint64          `json:"windowOverflow"`
	BaselineBytes     *int64          `json:"baselineBytes"`
	BaselineWrittenAt int64           `json:"baselineWrittenAt"`
	AlertBytes        *int64          `json:"alertBytes"`
	StorageError      string          `json:"storageError,omitempty"`
}

func BuildHealth(state Snapshot, baseline, output string, active bool, capture *CaptureHealth, delivery *DeliveryHealth) Health {
	h := Health{Schema: 1, SampledAt: time.Now().UnixMilli(), Active: active, Scopes: []Scope{}, Capture: capture, Delivery: delivery,
		DetectorError: state.Error, Observations: state.Samples, FactOverflow: state.Overflow, WindowOverflow: state.WindowOverflow}
	scopes := make(map[string]Scope)
	for _, observation := range state.Observed {
		data, _ := json.Marshal(observation.Fact.Scope)
		scopes[string(data)] = observation.Fact.Scope
	}
	keys := make([]string, 0, len(scopes))
	for key := range scopes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	h.ScopesTruncated = len(keys) > 128
	if len(keys) > 128 {
		keys = keys[:128]
	}
	scopeBytes := 0
	for _, key := range keys {
		if scopeBytes+len(key) > 48<<10 {
			h.ScopesTruncated = true
			break
		}
		scopeBytes += len(key)
		h.Scopes = append(h.Scopes, scopes[key])
	}
	if info, err := os.Stat(baseline); err == nil {
		size := info.Size()
		h.BaselineBytes = &size
		h.BaselineWrittenAt = info.ModTime().UnixMilli()
	} else if !errors.Is(err, os.ErrNotExist) || state.Mode != Learning || state.Version != 0 {
		h.StorageError = err.Error()
	}
	if info, err := os.Stat(filepath.Join(output, "Alert.ncap.gz")); err == nil {
		size := info.Size()
		h.AlertBytes = &size
	} else if !errors.Is(err, os.ErrNotExist) {
		h.StorageError = errors.Join(errors.New(h.StorageError), err).Error()
	}
	return h
}

func (e *Engine) Health(output string, capture *CaptureHealth, delivery *DeliveryHealth) Health {
	return BuildHealth(e.Snapshot(), e.config.Path, output, true, capture, delivery)
}

func WriteHealth(output string, health Health) error {
	data, err := json.Marshal(health)
	if err != nil {
		return err
	}
	if len(data) > 64<<10 {
		return errors.New("behavioral health exceeds 64 KiB")
	}
	return writeBehaviorFile(filepath.Join(output, HealthFilename), data)
}

func ReadHealth(output string) (Health, error) {
	file, err := os.Open(filepath.Join(output, HealthFilename))
	if err != nil {
		return Health{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil {
		return Health{}, err
	}
	if len(data) > 64<<10 {
		return Health{}, errors.New("behavioral health exceeds 64 KiB")
	}
	var health Health
	if err := json.Unmarshal(data, &health); err != nil {
		return Health{}, err
	}
	if health.Schema != 1 || len(health.Scopes) > 128 {
		return Health{}, errors.New("invalid behavioral health schema or scopes")
	}
	return health, nil
}
