package enforcer

import (
	"context"
	"sync"
	"time"
)

// DryRunBackend is an unprivileged in-memory simulator. It executes no commands.
type DryRunBackend struct {
	mu     sync.Mutex
	leases map[string]Lease
}

func NewDryRunBackend() *DryRunBackend { return &DryRunBackend{leases: make(map[string]Lease)} }
func (b *DryRunBackend) Apply(ctx context.Context, l Lease) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if old, ok := b.leases[l.ID]; ok && old.ExpiresAt.After(time.Now()) && old != l {
		return ErrConflict
	}
	if l.ExpiresAt.After(time.Now()) {
		b.leases[l.ID] = l
	}
	return nil
}
func (b *DryRunBackend) Delete(ctx context.Context, l Lease) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if old, ok := b.leases[l.ID]; ok && old != l {
		return ErrConflict
	}
	delete(b.leases, l.ID)
	return nil
}
func (b *DryRunBackend) List(ctx context.Context) ([]Lease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, l := range b.leases {
		if !l.ExpiresAt.After(time.Now()) {
			delete(b.leases, id)
		}
	}
	return sorted(b.leases), nil
}
