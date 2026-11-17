package capture

import (
	"context"
	"testing"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/urfave/cli/v3"
)

func TestCaptureBudgetFlagResolution(t *testing.T) {
	for _, tc := range []struct {
		env  string
		args []string
		want int64
	}{
		{"", nil, defaults.MaxRetainedTCPBytes},
		{"12345", nil, 12345},
		{"12345", []string{"--max-retained-tcp-bytes=0"}, 0},
		{"invalid", []string{"--max-retained-tcp-bytes=17"}, 17},
	} {
		t.Run(tc.env+"/flag", func(t *testing.T) {
			if tc.env != "" {
				t.Setenv("NC_MAX_RETAINED_TCP_BYTES", tc.env)
			}
			command := &cli.Command{Flags: GetFlags(), Action: func(_ context.Context, c *cli.Command) error {
				if got := c.Int64("max-retained-tcp-bytes"); got != tc.want {
					t.Fatal("resolved TCP budget", got, tc.want)
				}
				return nil
			}}
			if err := command.Run(context.Background(), append([]string{"capture"}, tc.args...)); err != nil {
				t.Fatal(err)
			}
		})
	}
}
