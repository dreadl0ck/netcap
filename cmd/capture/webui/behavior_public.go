package webui

import "github.com/dreadl0ck/netcap/internal/behavior"

const BehaviorSnapshotName = "Behavior.json"
const BehaviorHealthName = behavior.HealthFilename

type BehaviorHealth = behavior.Health

// ValidateBehaviorSnapshot preserves the module's format boundary for desktop consumers.
func ValidateBehaviorSnapshot(path string) error {
	_, err := behavior.ReadSnapshot(path)
	return err
}
