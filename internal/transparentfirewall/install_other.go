//go:build !linux

package transparentfirewall

import (
	"context"
	"errors"
)

func Install(context.Context, Config) (func() error, error) {
	return nil, errors.New("transparent TCP placement requires Linux nftables and a named network namespace")
}
