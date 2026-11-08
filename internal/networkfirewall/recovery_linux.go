//go:build linux

package networkfirewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

type ownershipRecord struct {
	Nonce      string `json:"nonce"`
	Scope      string `json:"scope"`
	Table      string `json:"table"`
	Generation uint64 `json:"generation"`
}

// PrepareOwned installs persistent missing-listener-deny hooks before routing.
func PrepareOwned(ctx context.Context, c Config) error {
	return ProvisionOwned(ctx, c, func() error { return nil })
}

// ProvisionOwned holds the packet-owner fences and persistent deny hooks while
// a supervisor reconciles topology. The callback must not reacquire these fences.
func ProvisionOwned(ctx context.Context, c Config, provision func() error) error {
	if c.OwnershipNonce == "" {
		return errors.New("ownership nonce required")
	}
	f, err := New(c, bootstrapDeny{})
	if err != nil {
		return err
	}
	return withOwned(f, func(ns, lock *os.File) error {
		st, e := lock.Stat()
		if e != nil {
			return e
		}
		f.config.RecoverOwned = st.Size() != 0
		if err := f.install(ctx, ns, lock); err != nil {
			return err
		}
		return provision()
	})
}

type bootstrapDeny struct{}

func (bootstrapDeny) EvaluatePacket(PacketEvent) (Decision, error) {
	return Decision{Verdict: Deny}, nil
}

// RetireOwned retains both fences and fail-closed hooks throughout retirement.
func RetireOwned(ctx context.Context, c Config, retire func() error) error {
	f, err := New(c, bootstrapDeny{})
	if err != nil {
		return err
	}
	if c.OwnershipNonce == "" {
		return errors.New("ownership nonce required")
	}
	return withOwned(f, func(ns, lock *os.File) error {
		st, err := lock.Stat()
		if err != nil {
			return err
		}
		if st.Size() == 0 {
			cmd := exec.CommandContext(ctx, "nsenter", "--net=/proc/self/fd/3", "--", "nft", "-j", "list", "tables")
			cmd.ExtraFiles = []*os.File{ns}
			b, err := cmd.Output()
			if err != nil {
				return err
			}
			var tables struct {
				NFT []struct {
					Table *struct {
						Family string `json:"family"`
						Name   string `json:"name"`
					} `json:"table"`
				} `json:"nftables"`
			}
			if err = json.Unmarshal(b, &tables); err != nil {
				return err
			}
			for _, t := range tables.NFT {
				if t.Table != nil && t.Table.Family == "inet" && t.Table.Name == tableName {
					return errors.New("uncommitted packet ownership; operator inspection required")
				}
			}
			return retire()
		}
		f.config.RecoverOwned = true
		if err := f.install(ctx, ns, lock); err != nil {
			return err
		}
		if err := retire(); err != nil {
			return err
		}
		// The namespace is gone while its descriptor and both fences remain
		// pinned. Clear its history before the kernel can reuse the inode.
		if err := lock.Truncate(0); err != nil {
			return err
		}
		return lock.Sync()
	})
}
func withOwned(f *Firewall, fn func(*os.File, *os.File) error) error {
	ns, err := openNamespace(f.config.Namespace)
	if err != nil {
		return err
	}
	defer ns.Close()
	fd, err := kernelFence(ns)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	lock, err := lockNamespace(ns, fd)
	if err != nil {
		return err
	}
	defer lock.Close()
	return fn(ns, lock)
}

func tableSnapshot(ctx context.Context, ns *os.File) (string, error) {
	c := exec.CommandContext(ctx, "nsenter", "--net=/proc/self/fd/3", "--", "nft", "-s", "list", "table", "inet", tableName)
	c.ExtraFiles = []*os.File{ns}
	b, err := c.Output()
	return string(b), err
}

// The stable root-owned lock inode is also the recovery journal. Never unlink
// it or place competing supervisors in different /run mount namespaces.
func (f *Firewall) install(ctx context.Context, ns, lock *os.File) error {
	if f.config.OwnershipNonce == "" {
		return runNFT(ctx, ns, f.rules())
	}
	c := f.config
	scope := fmt.Sprintf("%x", sha256.Sum256([]byte(c.OwnershipNonce+"\n"+f.rules())))
	r := ownershipRecord{Nonce: c.OwnershipNonce, Scope: scope, Generation: 1}
	var committed int64
	if f.config.RecoverOwned {
		data, err := io.ReadAll(io.LimitReader(lock, (1<<20)+1))
		if err != nil {
			return err
		}
		if len(data) > 1<<20 {
			return errors.New("ownership journal full; operator compaction required")
		}
		for _, line := range bytes.SplitAfter(data, []byte{'\n'}) {
			if len(line) == 0 || line[len(line)-1] != '\n' {
				break
			}
			if err = json.Unmarshal(line, &r); err != nil {
				return errors.New("corrupt ownership journal; operator inspection required")
			}
			committed += int64(len(line))
		}
		if committed == 0 {
			return errors.New("no complete ownership journal; operator inspection required")
		}
		if r.Nonce != c.OwnershipNonce || r.Scope != scope || r.Table == "" {
			return errors.New("immutable appliance ownership/scope mismatch")
		}
		observed, err := tableSnapshot(ctx, ns)
		if err != nil {
			return err
		}
		if observed != r.Table {
			return errors.New("owned table drift; refusing recovery or cleanup")
		}
		if r.Generation == ^uint64(0) {
			return errors.New("ownership generation exhausted")
		}
		r.Generation++
	} else {
		info, err := lock.Stat()
		if err != nil {
			return err
		}
		if info.Size() != 0 {
			return errors.New("persistent journal exists; use explicit recover")
		}
		if err = runNFT(ctx, ns, f.rules()); err != nil {
			return err
		}
		r.Table, err = tableSnapshot(ctx, ns)
		if err != nil {
			return err
		}
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	// Keep the previous committed generation across a torn append. Only an
	// incomplete tail is discarded, while the stable flock inode stays pinned.
	if err = lock.Truncate(committed); err != nil {
		return err
	}
	if _, err = lock.WriteAt(data, committed); err != nil {
		return err
	}
	return lock.Sync()
}
