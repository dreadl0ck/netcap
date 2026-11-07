//go:build !linux

package enforcer

import (
	"context"
	"errors"
)

type NFTBackend struct{}

func (*NFTBackend) Close() error { return nil }

func NewNFTBackend(Config) (*NFTBackend, error) {
	return nil, errors.New("nftables enforcer requires Linux; use DryRunBackend")
}
func (*NFTBackend) Apply(context.Context, Lease) error  { return errors.New("nftables requires Linux") }
func (*NFTBackend) Delete(context.Context, Lease) error { return errors.New("nftables requires Linux") }
func (*NFTBackend) List(context.Context) ([]Lease, error) {
	return nil, errors.New("nftables requires Linux")
}
