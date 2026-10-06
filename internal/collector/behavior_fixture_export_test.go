package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/internal/behavior"
	"github.com/gopacket/gopacket/pcapgo"
)

func behaviorFixtureDirectory(t *testing.T, name string) string {
	t.Helper()
	root := os.Getenv("NETCAP_BEHAVIOR_EXPORT")
	if root == "" {
		return t.TempDir()
	}
	if !filepath.IsAbs(root) {
		t.Fatal("fixture export requires an absolute directory")
	}
	reference, err := hex.DecodeString(os.Getenv("NETCAP_BEHAVIOR_REFERENCE"))
	if err != nil || len(reference) != 20 {
		t.Fatal("fixture export requires a 40-character Go reference commit")
	}
	dir := filepath.Join(root, name)
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("export requires a fresh fixture directory", dir)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func exportBehaviorSeed(t *testing.T, root string, engine *behavior.Engine) {
	t.Helper()
	if os.Getenv("NETCAP_BEHAVIOR_EXPORT") == "" {
		return
	}
	data, err := json.MarshalIndent(engine.Snapshot(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "baseline.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func exportBehaviorResult(t *testing.T, root string, alerts []string, geo bool, inputs ...string) {
	t.Helper()
	if os.Getenv("NETCAP_BEHAVIOR_EXPORT") == "" {
		return
	}
	file, err := os.Create(filepath.Join(root, "monitoring.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	writer := pcapgo.NewWriter(file)
	for index, path := range inputs {
		input, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		reader, err := pcapgo.NewReader(input)
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			if err := writer.WriteFileHeader(65535, reader.LinkType()); err != nil {
				t.Fatal(err)
			}
		}
		for {
			data, info, err := reader.ReadPacketData()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := writer.WritePacket(info, data); err != nil {
				t.Fatal(err)
			}
		}
		input.Close()
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(alerts, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "alerts.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	hashes := map[string]string{}
	paths := []string{"baseline.json", "monitoring.pcap", "alerts.json"}
	if geo {
		entries, err := os.ReadDir(filepath.Join(root, "dbs"))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			paths = append(paths, filepath.Join("dbs", entry.Name()))
		}
	}
	for _, path := range paths {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(data)
		hashes[filepath.ToSlash(path)] = hex.EncodeToString(hash[:])
	}
	manifest := map[string]any{"contract": 1, "schema": behavior.SchemaVersion, "sensor": "replay", "interface": "pcap", "geolocation": geo, "referenceCommit": os.Getenv("NETCAP_BEHAVIOR_REFERENCE"), "sha256": hashes}
	data, err = json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}
