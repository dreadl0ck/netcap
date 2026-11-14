package collector

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/internal/utils"
)

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
