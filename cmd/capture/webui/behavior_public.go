package webui

import (
	"errors"
	"github.com/dreadl0ck/netcap/internal/behavior"
	"path/filepath"
)

const BehaviorSnapshotName = "Behavior.json"
const BehaviorHealthName = behavior.HealthFilename

type BehaviorHealth = behavior.Health

// ValidateBehaviorSnapshot preserves the module's format boundary for desktop consumers.
func ValidateBehaviorSnapshot(path string) error {
	_, err := behavior.ReadSnapshot(path)
	return err
}

func ValidateBehaviorHealth(path string) error {
	if filepath.Base(path) != BehaviorHealthName {
		return errors.New("invalid behavioral health filename")
	}
	_, err := behavior.ReadHealth(filepath.Dir(path))
	return err
}
