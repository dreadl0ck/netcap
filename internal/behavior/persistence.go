package behavior

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const maxSnapshotBytes = 64 << 20

func ReadSnapshot(path string) (Snapshot, error) {
	file, err := os.Open(path)
	if err != nil {
		return Snapshot{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxSnapshotBytes+1))
	if err != nil {
		return Snapshot{}, err
	}
	if len(data) > maxSnapshotBytes {
		return Snapshot{}, errors.New("baseline snapshot exceeds size limit")
	}
	var state Snapshot
	if err := json.Unmarshal(data, &state); err != nil {
		return state, fmt.Errorf("invalid baseline snapshot: %w", err)
	}
	if state.Schema == 1 {
		state.Schema = SchemaVersion
		state.Policy = DefaultPolicy()
		state.Activity = make(map[string]Activity)
		state.Rates = make(map[string]RateStats)
		state.ApprovedRates = make(map[string]RateModel)
	} else if state.Schema != SchemaVersion {
		return state, fmt.Errorf("unsupported baseline schema %d", state.Schema)
	}
	if err := validatePolicy(state.Policy); err != nil {
		return state, err
	}
	if state.Rates == nil || state.ApprovedRates == nil || len(state.Rates) > state.MaxFacts || len(state.ApprovedRates) > state.MaxFacts {
		return state, errors.New("invalid rate bounds")
	}
	for id, rate := range state.Rates {
		fact := rate.Fact
		if err := fact.normalize(); err != nil {
			return state, err
		}
		if fact.Kind != "traffic" || id != factID(fact) || rate.Start <= 0 || !validRateModel(rate.Model) {
			return state, errors.New("invalid rate state")
		}
	}
	for id, model := range state.ApprovedRates {
		if _, ok := state.Approved[id]; !ok || !validRateModel(model) {
			return state, errors.New("invalid approved rate")
		}
	}
	if state.Activity == nil || len(state.Activity) > state.MaxFacts {
		return state, errors.New("invalid activity bounds")
	}
	for key, activity := range state.Activity {
		fact := activity.Fact
		if err := fact.normalize(); err != nil {
			return state, err
		}
		if fact.Kind != "service" || fact.Token == "" || activity.At <= 0 || key != activityKey(fact) {
			return state, errors.New("invalid activity event")
		}
	}
	if state.Mode != Learning && state.Mode != Monitoring && state.Mode != Paused {
		return state, errors.New("invalid baseline mode")
	}
	if state.Mode == Paused && state.ResumeMode != Learning && state.ResumeMode != Monitoring {
		return state, errors.New("invalid paused mode")
	}
	if state.MinLearningNS < 0 || state.MinSamples == 0 || state.MaxFacts < 1 || state.MaxFacts > 100000 || len(state.Observed) > state.MaxFacts || len(state.Approved) > state.MaxFacts || len(state.Decisions) > 1000 || len(state.Suppressed) > state.MaxFacts {
		return state, errors.New("invalid baseline bounds")
	}
	if state.Observed == nil || state.Approved == nil || state.Suppressed == nil {
		return state, errors.New("baseline maps are required")
	}
	for id, observation := range state.Observed {
		fact := observation.Fact
		if err := fact.normalize(); err != nil {
			return state, err
		}
		if id != factID(fact) || observation.Samples == 0 || observation.FirstSeen <= 0 || observation.LastSeen < observation.FirstSeen {
			return state, errors.New("invalid observation identity or timestamps")
		}
	}
	for id, fact := range state.Approved {
		if err := fact.normalize(); err != nil {
			return state, err
		}
		if id != factID(fact) {
			return state, errors.New("invalid approved fact identity")
		}
	}
	for id, reason := range state.Suppressed {
		if _, ok := state.Observed[id]; !ok || reason == "" || len(reason) > 1024 {
			return state, errors.New("invalid suppression")
		}
	}
	if state.Version > 0 && state.BaselineID != baselineStateID(state.Approved, state.ApprovedRates) {
		return state, errors.New("baseline content identity mismatch")
	}
	if (state.Mode == Monitoring || state.ResumeMode == Monitoring) && (state.Version == 0 || len(state.Approved) == 0) {
		return state, errors.New("monitoring requires an approved baseline")
	}
	return state, nil
}

func writeSnapshot(path string, state Snapshot) (err error) {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if len(data) > maxSnapshotBytes {
		return errors.New("baseline snapshot exceeds size limit")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".behavior-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err := file.Write(data); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := file.Sync(); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
