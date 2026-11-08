//go:build !linux

package networkfirewall

import (
	"context"
	"errors"
)

func (f *Firewall) Run(context.Context) error {
	return errors.New("network firewall requires Linux NFQUEUE, nftables and a named network namespace")
}
