//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package enforcer

import (
	"errors"
)

func lockState(string) (func() error, error) {
	return nil, errors.New("persistent enforcer state requires a platform with flock; use in-memory dry-run")
}
