package investigate

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/internal/protocoltest"
)

func TestProtocolCorpusAndTriageCLI(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.bin")
	artifact := filepath.Join(dir, "stack.txt")
	for p, b := range map[string][]byte{input: []byte{0, 1, 255}, artifact: []byte("external fixture stack\n")} {
		if err := os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	var output bytes.Buffer
	cmd := GetCommand()
	cmd.Writer = &output
	if err := cmd.Run(context.Background(), []string{"investigate", "protocol-corpus", "--read", input}); err != nil {
		t.Fatal(err)
	}
	var corpus []protocoltest.CorpusCase
	if err := json.Unmarshal(output.Bytes(), &corpus); err != nil || len(corpus) != 7 {
		t.Fatal("corpus CLI", err, output.String())
	}
	output.Reset()
	cmd = GetCommand()
	cmd.Writer = &output
	if err := cmd.Run(context.Background(), []string{"investigate", "protocol-triage", "--read", input, "--artifact", artifact, "--kind", "stack", "--target-version", "fixture-1", "--reset", "restart fixture"}); err != nil {
		t.Fatal(err)
	}
	var report protocoltest.TriageArtifact
	if err := json.Unmarshal(output.Bytes(), &report); err != nil || report.Classification != "external evidence; impact unverified" || !bytes.Equal(report.Input, corpus[0].Input) {
		t.Fatal("triage CLI", err, output.String())
	}
}

func TestProtocolWorkflowCommandsRejectUnknownSpecifications(t *testing.T) {
	file := filepath.Join(t.TempDir(), "unknown.json")
	if err := os.WriteFile(file, []byte(`{"unexpected":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"protocol-server", "protocol-access", "protocol-fuzz"} {
		t.Run(name, func(t *testing.T) {
			cmd := GetCommand()
			var output bytes.Buffer
			cmd.Writer = &output
			cmd.ErrWriter = &output
			if err := cmd.Run(context.Background(), []string{"investigate", name, "--spec", file}); err == nil {
				t.Fatal("unknown specification accepted")
			}
		})
	}
}
