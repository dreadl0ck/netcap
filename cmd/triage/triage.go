package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/dreadl0ck/netcap/internal/identity"
	"github.com/dreadl0ck/netcap/internal/table"
	"github.com/urfave/cli/v3"
)

func GetCommand() *cli.Command {
	return &cli.Command{Name: "triage", Usage: "show capture-derived hosts, identities and conflicting observations", Flags: []cli.Flag{&cli.StringFlag{Name: "read", Required: true, Usage: "capture output directory or Hosts.json"}, &cli.BoolFlag{Name: "json", Usage: "include all provenance and binding observations as JSON"}}, Action: Run}
}
func Run(_ context.Context, c *cli.Command) error {
	path := c.String("read")
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		path = filepath.Join(path, identity.Filename)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var report identity.Report
	decoder := json.NewDecoder(io.LimitReader(f, 64<<20))
	if err := decoder.Decode(&report); err != nil {
		return err
	}
	if report.Schema != 1 {
		return fmt.Errorf("unsupported host identity schema %d", report.Schema)
	}
	if c.Bool("json") {
		enc := json.NewEncoder(c.Writer)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	var rows [][]string
	for _, h := range report.Hosts {
		var users, full []string
		for _, a := range h.Accounts {
			name := a.Name
			if a.Domain != "" {
				name = a.Domain + "\\" + name
			}
			users = append(users, name)
			if a.FullName != "" {
				full = append(full, a.FullName)
			}
		}
		mac := h.MAC
		if mac != "" && h.MACState != "binding-observed" {
			mac += " (observed)"
		}
		rows = append(rows, []string{h.IP, mac, h.Hostname, strings.Join(users, "; "), strings.Join(full, "; "), h.HostnameState + " / " + h.MACState})
	}
	table.Render(c.Writer, []string{"IP", "MAC", "Host name", "Account", "Full name", "Evidence state"}, rows)
	if len(report.Directory) > 0 {
		fmt.Fprintln(c.Writer, "Directory subjects (account/host association requires matching evidence):")
		var subjects [][]string
		for _, d := range report.Directory {
			subjects = append(subjects, []string{d.Account, d.Domain, d.FullName, d.Evidence.Source})
		}
		table.Render(c.Writer, []string{"Account", "Domain", "Full name", "Source"}, subjects)
	}
	if report.Overflow > 0 {
		fmt.Fprintf(c.Writer, "Bounded-state limit reached: %d observations omitted\n", report.Overflow)
	}
	return nil
}
