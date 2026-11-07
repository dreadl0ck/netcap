//go:build !linux

package appliance

import (
	"context"
	"errors"
)

func Execute(context.Context, Manifest, string, string) (any, error) {
	return nil, errors.New("appliance topology requires Linux in a disposable lab container")
}
