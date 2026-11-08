package firewallstate

import (
	"context"
	"github.com/dreadl0ck/netcap/internal/firewallauth"
)

func (d *Database) AuthNamespace() string { return d.authEndpoint }

func (d *Database) AuthTransaction(ctx context.Context, f func(firewallauth.SQLTransaction) error) error {
	tx, err := d.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = f(tx); err != nil {
		return err
	}
	return tx.Commit()
}
