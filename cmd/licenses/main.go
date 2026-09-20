package licenses

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/dreadl0ck/netcap"
)

// GetFlags returns the command flags.
func GetFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:  "all",
			Usage: "print all bundled license documents",
		},
	}
}

// RunWithContext runs the licenses command.
func RunWithContext(_ context.Context, cmd *cli.Command) error {
	return Run(cmd.Writer, cmd.Args().Slice(), cmd.Bool("all"))
}

// Run lists or prints bundled license documents.
func Run(output io.Writer, args []string, all bool) error {
	if all && len(args) != 0 {
		return fmt.Errorf("--all does not accept a document name")
	}
	if len(args) > 1 {
		return fmt.Errorf("expected at most one license document, got %d", len(args))
	}

	if all {
		for index, name := range netcap.LicenseNames() {
			if index > 0 {
				_, _ = fmt.Fprintln(output)
			}
			if _, err := fmt.Fprintf(output, "===== %s =====\n", name); err != nil {
				return err
			}
			if err := writeDocument(output, name); err != nil {
				return err
			}
		}
		return nil
	}

	if len(args) == 0 {
		for _, name := range netcap.LicenseNames() {
			if _, err := fmt.Fprintln(output, name); err != nil {
				return err
			}
		}
		return nil
	}

	return writeDocument(output, args[0])
}

func writeDocument(output io.Writer, name string) error {
	text, err := netcap.ReadLicense(name)
	if err != nil {
		return err
	}
	if _, err = output.Write(text); err != nil {
		return err
	}
	if !strings.HasSuffix(string(text), "\n") {
		_, err = fmt.Fprintln(output)
	}
	return err
}
