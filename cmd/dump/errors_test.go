package dump

import (
	"context"
	"github.com/urfave/cli/v3"
	"strings"
	"testing"
)

func TestDumpReturnsActionableErrors(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"dump"}, "requires --read"},
		{[]string{"dump", "--read", "traffic.pcap"}, "net capture"},
		{[]string{"dump", "--read", "audit.txt"}, "unsupported audit file extension"},
		{[]string{"dump", "--read", "missing.ncap", "--header"}, "open audit header"},
		{[]string{"dump", "--read", "missing.ncap", "--json"}, "failed to open audit record"},
	} {
		c := &cli.Command{Flags: GetFlags(), Action: RunWithContext}
		if err := c.Run(context.Background(), tc.args); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%v: %v", tc.args, err)
		}
	}
}
