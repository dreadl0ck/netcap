package enforcer

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

type snapshot struct {
	Version   int     `json:"version"`
	ScopeHash string  `json:"scope_hash"`
	Leases    []Lease `json:"leases"`
}

func (c *Controller) load() error {
	f, err := os.Open(c.config.StateFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("state file must be private (0600)")
	}
	var s snapshot
	d := json.NewDecoder(io.LimitReader(f, 2<<20))
	d.DisallowUnknownFields()
	if err = d.Decode(&s); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing state data")
	}
	if s.Version != 1 || s.ScopeHash != fingerprint(c.config) {
		return errors.New("state scope/version mismatch")
	}
	if len(s.Leases) > c.config.MaxLeases {
		return ErrLimit
	}
	selectors := make(map[string]bool)
	for _, l := range s.Leases {
		if err = c.validate(l); err != nil {
			return err
		}
		if _, ok := c.leases[l.ID]; ok || selectors[l.Source] {
			return ErrConflict
		}
		c.leases[l.ID] = l
		selectors[l.Source] = true
	}
	return nil
}

func (c *Controller) save() error {
	if c.config.StateFile == "" {
		return nil
	}
	data, err := json.Marshal(snapshot{1, fingerprint(c.config), sorted(c.leases)})
	if err != nil {
		return err
	}
	dir := filepath.Dir(c.config.StateFile)
	f, err := os.CreateTemp(dir, ".enforcer-*")
	if err != nil {
		return &ExecutionError{err}
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(f.Name(), c.config.StateFile)
	}
	if err == nil {
		var d *os.File
		d, err = os.Open(dir)
		if err == nil {
			err = d.Sync()
			_ = d.Close()
		}
	}
	if err != nil {
		return &ExecutionError{err}
	}
	return nil
}
