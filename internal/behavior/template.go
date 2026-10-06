package behavior

import (
	"errors"
	"os"
	"path/filepath"
)

// SeedTemplate copies a validated snapshot into a new session, never overwriting
// an existing session baseline or allowing that session to mutate the source.
func SeedTemplate(source, target string) error {
	state, err := ReadSnapshot(source)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		return err
	}
	lease, err := os.OpenFile(target+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lease.Close()
	if err := lockBaseline(lease); err != nil {
		return err
	}
	if _, err := os.Stat(target); err == nil {
		_, err = ReadSnapshot(target)
		return err
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeSnapshot(target, state)
}
