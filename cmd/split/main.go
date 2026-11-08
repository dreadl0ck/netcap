package split

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/urfave/cli/v3"
)

func GetCommand() *cli.Command {
	return &cli.Command{Name: "split", Usage: "export one bounded BPF/time packet subset with a provenance manifest", Flags: GetFlags(), Action: RunWithContext}
}

func Run() {
	if err := GetCommand().Run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

func RunWithContext(ctx context.Context, c *cli.Command) error {
	selection := evidence.Selection{BPF: strings.TrimSpace(c.String("bpf")), MaxPackets: c.Int("max-packets")}
	start, end := c.String("start-ns"), c.String("end-ns")
	if (start == "") != (end == "") {
		return fmt.Errorf("start-ns and end-ns must be supplied together")
	}
	if start != "" {
		a, err := strconv.ParseInt(start, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid start-ns: %w", err)
		}
		b, err := strconv.ParseInt(end, 10, 64)
		if err != nil || b < a {
			return fmt.Errorf("invalid end-ns or reversed time range")
		}
		selection.StartNs, selection.EndNs = &a, &b
	}
	if selection.BPF == "" && selection.StartNs == nil {
		return fmt.Errorf("a BPF or inclusive time selection is required")
	}
	if len(selection.BPF) > 8192 || selection.MaxPackets < 1 || selection.MaxPackets > 1_000_000 {
		return fmt.Errorf("BPF/packet limit exceeds supported bounds")
	}
	limit := c.Int64("max-bytes")
	if limit < 1 || limit > 1<<30 {
		return fmt.Errorf("max-bytes must be 1–1073741824")
	}
	input, out := c.String("read"), c.String("out")
	if input == "" || out == "" {
		return fmt.Errorf("read and out are required")
	}
	info, err := os.Lstat(input)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("source must be a regular file, not a symlink")
	}
	// Reserve the destination first: existing files/directories are never replaced.
	if err := os.Mkdir(out, 0700); err != nil {
		return fmt.Errorf("reserve output: %w", err)
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(out)
		}
	}()
	f, err := os.OpenFile(filepath.Join(out, "selected.pcapng"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	writer := &boundedWriter{output: f, remaining: limit}
	manifest, exportErr := evidence.ExportPackets(ctx, input, writer, selection)
	if exportErr == nil {
		exportErr = f.Sync()
	}
	closeErr := f.Close()
	if exportErr != nil {
		return exportErr
	}
	if closeErr != nil {
		return closeErr
	}
	if manifest.Selected == 0 {
		return fmt.Errorf("selection matched no packets")
	}
	if expected := c.String("source-sha256"); expected != "" && !strings.EqualFold(expected, manifest.SourceSHA256) {
		return fmt.Errorf("source SHA256 mismatch")
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "packet-selection.json"), data, 0600); err != nil {
		return err
	}
	complete = true
	_, err = fmt.Fprintln(c.Writer, string(data))
	return err
}

type boundedWriter struct {
	output    io.Writer
	remaining int64
}

func (w *boundedWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > w.remaining {
		return 0, fmt.Errorf("packet subset output byte limit exceeded")
	}
	n, err := w.output.Write(data)
	w.remaining -= int64(n)
	return n, err
}
