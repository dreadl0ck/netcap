package split

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/urfave/cli/v3"
)

type timeShard struct {
	File     string                  `json:"file,omitempty"`
	State    string                  `json:"state"`
	Manifest evidence.PacketManifest `json:"manifest"`
}
type splitManifest struct {
	Version      int         `json:"version"`
	SourceSHA256 string      `json:"sourceSHA256"`
	Shards       []timeShard `json:"shards"`
	Limitations  []string    `json:"limitations"`
}

func splitTimeShards(ctx context.Context, c *cli.Command, selection evidence.Selection, limit int64) error {
	width, err := strconv.ParseInt(c.String("shard-ns"), 10, 64)
	if err != nil || width <= 0 || selection.StartNs == nil || *selection.StartNs < 0 {
		return fmt.Errorf("positive shard width and nonnegative inclusive time bounds required")
	}
	start, end := *selection.StartNs, *selection.EndNs
	if (end-start)/width >= 16 {
		return fmt.Errorf("time selection exceeds 16 shards")
	}
	out := c.String("out")
	if err = os.Mkdir(out, 0700); err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(out)
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	result := splitManifest{Version: 1, Shards: []timeShard{}, Limitations: []string{"Only explicitly selected BPF/time traffic is included; non-overlapping inclusive windows partition selected packets", "Empty windows are recorded without an empty PCAP; original capture and packet-selection limitations still apply"}}
	writer := &boundedWriter{remaining: limit}
	selectedTotal := uint64(0)
	for index := 0; ; index++ {
		last := end
		if end-start >= width {
			last = start + width - 1
		}
		first := start
		part := selection
		part.StartNs = &first
		part.EndNs = &last
		name := fmt.Sprintf("shard-%02d.pcapng", index+1)
		f, e := os.OpenFile(filepath.Join(out, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		writer.output = f
		manifest, e := evidence.ExportPackets(ctx, c.String("read"), writer, part)
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
		if result.SourceSHA256 == "" {
			result.SourceSHA256 = manifest.SourceSHA256
		} else if result.SourceSHA256 != manifest.SourceSHA256 {
			return fmt.Errorf("source changed between shards")
		}
		if expected := c.String("source-sha256"); expected != "" && !strings.EqualFold(expected, manifest.SourceSHA256) {
			return fmt.Errorf("source SHA256 mismatch")
		}
		selectedTotal += manifest.Selected
		if selectedTotal > uint64(selection.MaxPackets) {
			return fmt.Errorf("total selected packet limit exceeded")
		}
		shard := timeShard{File: name, State: "complete", Manifest: manifest}
		if manifest.Selected == 0 {
			if e = os.Remove(filepath.Join(out, name)); e != nil {
				return e
			}
			shard.File = ""
			shard.State = "empty-window"
		}
		result.Shards = append(result.Shards, shard)
		if last == end {
			break
		}
		start = last + 1
	}
	if selectedTotal == 0 {
		return fmt.Errorf("selection matched no packets")
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(out, "split-manifest.json"), data, 0600); err != nil {
		return err
	}
	complete = true
	return json.NewEncoder(c.Writer).Encode(result)
}
