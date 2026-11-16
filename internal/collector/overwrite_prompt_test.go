package collector

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/internal/utils"
)

func TestQuietDoesNotAuthorizeOverwrite(t *testing.T) {
	orig := utils.StdinIsTerminal
	utils.StdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { utils.StdinIsTerminal = orig })
	for _, quiet := range []bool{false, true} {
		for _, yes := range []bool{false, true} {
			c := lifecycleInitCollector(t)
			c.config.NoPrompt = yes
			c.config.DecoderConfig.Quiet = quiet
			path := filepath.Join(c.config.DecoderConfig.Out, "TCP.ncap.gz")
			original := []byte("original audit bytes")
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			tx, err := c.prepareOutputReplacement()
			if yes {
				if err != nil || tx == nil {
					t.Fatalf("explicit overwrite: %v", err)
				}
				if err := tx.rollback(); err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, errNotInteractive) || tx != nil {
				t.Fatalf("quiet=%t authorized overwrite: %v", quiet, err)
			}
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, original) {
				t.Fatalf("original output changed: %q %v", got, err)
			}
		}
	}
}

func TestInitRefusesToPromptWithoutTerminal(t *testing.T) {
	orig := utils.StdinIsTerminal
	utils.StdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { utils.StdinIsTerminal = orig })

	c := lifecycleInitCollector(t)
	c.config.NoPrompt = false
	c.config.DecoderConfig.Quiet = false
	if err := os.WriteFile(filepath.Join(c.config.DecoderConfig.Out, "TCP.ncap.gz"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := c.Init()
	if !errors.Is(err, errNotInteractive) {
		t.Fatalf("want errNotInteractive, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(c.config.DecoderConfig.Out, "TCP.ncap.gz")); statErr != nil {
		t.Fatal("previous output must be kept when the prompt cannot be answered:", statErr)
	}
}
