package transform

import (
	"context"
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/urfave/cli/v3"
	"os"
	"path/filepath"
	"testing"
)

func TestPopularityHTTPSelection(t *testing.T) {
	old := resolvers.CurrentConfig
	t.Cleanup(func() { resolvers.CurrentConfig = old; resolvers.InitDNSWhitelist() })
	p := filepath.Join(t.TempDir(), "list.csv")
	if err := os.WriteFile(p, []byte("1,example.co.uk\n2,alice.github.io\n"), 0600); err != nil {
		t.Fatal(err)
	}
	resolvers.CurrentConfig = resolvers.Config{DomainPopularityList: p}
	resolvers.InitDNSWhitelist()
	for _, tc := range []struct {
		src, host string
		want      bool
	}{{"local", "EXAMPLE.CO.UK:443", false}, {"other", "other.com", false}, {"local", "", false}, {"local", "bob.github.io:80", true}, {"local", "192.0.2.1:80", true}, {"local", "example.co.uk:bad", true}, {"local", "\u200d.de", true}} {
		if got := includePopularityHTTPHost(&types.HTTP{SrcIP: tc.src, Host: tc.host}, "local"); got != tc.want {
			t.Fatal(tc, got)
		}
	}
}
func TestPopularityFlagsPreserveMaltegoArguments(t *testing.T) {
	original := os.Args
	t.Cleanup(func() { os.Args = original })
	cmd := &cli.Command{Name: "transform", Flags: GetFlags(), Action: func(_ context.Context, c *cli.Command) error {
		if c.String("domain-popularity-list") != "/external/list.csv" || c.String("domain-popularity-format") != "netapi" || c.Args().Get(0) != "toHTTPHostsFiltered" || c.Args().Get(1) != "entity" {
			t.Fatal(c.Args().Slice())
		}
		return nil
	}}
	if err := cmd.Run(context.Background(), []string{"transform", "--domain-popularity-list", "/external/list.csv", "--domain-popularity-format", "netapi", "toHTTPHostsFiltered", "entity"}); err != nil {
		t.Fatal(err)
	}
}

func TestPopularityPreflightFailsBeforeDispatch(t *testing.T) {
	oldConfig, oldRoot := resolvers.CurrentConfig, resolvers.DataBaseFolderPath
	t.Cleanup(func() {
		resolvers.CurrentConfig, resolvers.DataBaseFolderPath = oldConfig, oldRoot
		resolvers.InitDNSWhitelist()
	})
	resolvers.DataBaseFolderPath = t.TempDir()
	resolvers.CurrentConfig = resolvers.Config{DomainPopularityFormat: "rank-domain"}
	if err := resolvers.InitDNSWhitelist(); err != nil {
		t.Fatalf("missing optional managed list: %v", err)
	}
	for _, args := range [][]string{
		{"transform", "--domain-popularity-list", filepath.Join(t.TempDir(), "missing.csv"), "toHTTPHostsFiltered"},
		{"transform", "--domain-popularity-format", "invalid", "toIncomingConnsFiltered"},
		{"transform", "--domain-popularity-list", filepath.Join(t.TempDir(), "missing.csv"), "toOutgoingConnsFiltered"},
	} {
		cmd := &cli.Command{Name: "transform", Flags: GetFlags(), Action: RunWithContext}
		if err := cmd.Run(context.Background(), args); err == nil {
			t.Fatal("missing list reached transform dispatch", args)
		}
	}
}
