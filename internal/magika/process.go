//go:build !nomagika

package magika

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

type Classifier struct {
	binary string
	info   os.FileInfo
	Digest string
}

func NewClassifier() (*Classifier, error) {
	path, err := exec.LookPath("magika")
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 256<<20 {
		return nil, fmt.Errorf("invalid Magika executable")
	}
	h := sha256.New()
	if _, err = io.Copy(h, io.LimitReader(f, (256<<20)+1)); err != nil {
		return nil, err
	}
	return &Classifier{binary: path, info: info, Digest: hex.EncodeToString(h.Sum(nil))}, nil
}

type cappedOutput struct {
	buffer   bytes.Buffer
	limit    int
	cancel   context.CancelFunc
	exceeded bool
}

func (w *cappedOutput) Write(p []byte) (int, error) {
	if len(p) > w.limit-w.buffer.Len() {
		w.exceeded = true
		w.cancel()
		return 0, fmt.Errorf("Magika output limit exceeded")
	}
	return w.buffer.Write(p)
}

func (c *Classifier) Classify(ctx context.Context, path string) (*Result, error) {
	info, err := os.Stat(c.binary)
	if err != nil || !os.SameFile(info, c.info) || info.Size() != c.info.Size() || !info.ModTime().Equal(c.info.ModTime()) {
		return nil, fmt.Errorf("Magika executable changed")
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	out := &cappedOutput{limit: 1 << 20, cancel: cancel}
	diagnostics := &cappedOutput{limit: 64 << 10, cancel: cancel}
	cmd := exec.CommandContext(ctx, c.binary, "--json", path)
	configureProcess(cmd)
	cmd.Stdout = out
	cmd.Stderr = diagnostics
	cmd.WaitDelay = 2 * time.Second
	err = cmd.Run()
	if out.exceeded || diagnostics.exceeded {
		return nil, fmt.Errorf("Magika output limit exceeded")
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, fmt.Errorf("Magika process: %w", err)
	}
	after, err := os.Stat(c.binary)
	if err != nil || !os.SameFile(after, c.info) || after.Size() != c.info.Size() || !after.ModTime().Equal(c.info.ModTime()) {
		return nil, fmt.Errorf("Magika executable changed")
	}
	result, err := parseJSONOutput(out.buffer.Bytes())
	if err != nil {
		return nil, err
	}
	if result == nil || result.Label == "" {
		return nil, errors.New("Magika returned no successful classification")
	}
	return result, nil
}

func (c *Classifier) ClassifyBytes(ctx context.Context, data []byte) (*Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(data) > 100<<20 {
		return nil, fmt.Errorf("Magika artifact exceeds 100 MiB")
	}
	f, err := os.CreateTemp("", "netcap-magika-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	_, writeErr := f.Write(data)
	if err := errors.Join(writeErr, f.Close()); err != nil {
		return nil, err
	}
	return c.Classify(ctx, f.Name())
}
