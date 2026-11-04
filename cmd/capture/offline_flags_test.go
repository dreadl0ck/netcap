package capture

import (
	"context"
	"github.com/urfave/cli/v3"
	"testing"
)

func TestOfflineHTTPOptIn(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"capture", "--read", "fixture.pcap"}, ""},
		{[]string{"capture", "--read", "fixture.pcap", "--http", "localhost:9090"}, "localhost:9090"},
		{[]string{"capture", "--read", "fixture.pcap", "--http", ""}, ""},
		{[]string{"capture", "--service"}, "localhost:8080"},
		{[]string{"capture"}, "localhost:8080"},
	} {
		cmd := &cli.Command{Flags: GetFlags(), Action: func(_ context.Context, c *cli.Command) error {
			setFlagsFromContext(c)
			if flagHTTP != tc.want {
				t.Errorf("%v: http=%q want %q", tc.args, flagHTTP, tc.want)
			}
			return nil
		}}
		if err := cmd.Run(context.Background(), tc.args); err != nil {
			t.Fatal(err)
		}
	}
}
