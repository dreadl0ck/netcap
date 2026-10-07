package collector

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/types"
)

func sensorTestStore(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestBookScopedSensorImport(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	keys := map[string][]byte{"inside": []byte(strings.Repeat("a", 32)), "outside": []byte(strings.Repeat("b", 32))}
	scope := SensorImportScope{SensorKeys: keys, Now: now, MaxBytes: 32 << 20, MaxRetention: 2 * time.Hour}
	store := sensorTestStore(t)
	outputs, bundles, imports, inputs := map[string]string{}, map[string]string{}, map[string]string{}, map[string]string{}
	for i, sensor := range []string{"inside", "outside"} {
		b, input := newBookCapture(t)
		inputs[sensor] = input
		src := "10.1.2.3"
		if i == 1 {
			src = "192.0.2.254"
		}
		b.conversation(src, "198.51.100.1", 60000, 80, false, bookMessage{false, "GET /two-sensor-marker HTTP/1.1\r\nHost: lab.invalid\r\n\r\n"}, bookMessage{true, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nLAB!"})
		outputs[sensor] = runBookCase(t, input, 2, false)
		bundle, err := SealSensorOutput(ctx, outputs[sensor], sensorTestStore(t), sensor, now, now.Add(time.Hour), keys[sensor])
		if err != nil {
			t.Fatal(err)
		}
		bundles[sensor] = bundle
	}
	insideOnly := scope
	insideOnly.SensorKeys = map[string][]byte{"inside": keys["inside"]}
	if _, err := ImportSensorOutput(ctx, bundles["outside"], store, insideOnly); err == nil {
		t.Fatal("unauthorized sensor accepted")
	}
	wrongKey := scope
	wrongKey.SensorKeys = map[string][]byte{"inside": []byte(strings.Repeat("x", 32))}
	if _, err := ImportSensorOutput(ctx, bundles["inside"], store, wrongKey); err == nil {
		t.Fatal("invalid sensor signature accepted")
	}
	for _, tc := range []struct {
		name   string
		change func(*SensorImportScope)
	}{
		{"expired", func(s *SensorImportScope) { s.Now = now.Add(2 * time.Hour) }},
		{"retention", func(s *SensorImportScope) { s.MaxRetention = time.Minute }},
		{"budget", func(s *SensorImportScope) { s.MaxBytes = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := scope
			tc.change(&bad)
			if _, err := ImportSensorOutput(ctx, bundles["inside"], store, bad); err == nil {
				t.Fatalf("%s restriction bypassed", tc.name)
			}
		})
	}
	for _, sensor := range []string{"inside", "outside"} {
		path, err := ImportSensorOutput(ctx, bundles[sensor], store, scope)
		if err != nil {
			t.Fatal(err)
		}
		imports[sensor] = path
		t.Run(sensor+"-imported", func(t *testing.T) {
			manifest := bookJSON[SensorManifest](t, filepath.Join(path, sensorManifestName))
			capture := bookJSON[evidence.CaptureManifest](t, filepath.Join(path, "capture-manifest.json"))
			if manifest.SensorID != sensor || manifest.RunID != capture.RunID || manifest.InputSHA256 != capture.InputSHA256 {
				t.Fatal("sensor identity detached from captured evidence")
			}
			for _, f := range manifest.Files {
				data, err := os.ReadFile(filepath.Join(path, f.Path))
				if err != nil {
					t.Fatal(err)
				}
				if fmt.Sprintf("%x", sha256.Sum256(data)) != f.SHA256 {
					t.Fatal("import content changed")
				}
				st, err := os.Stat(filepath.Join(path, f.Path))
				if err != nil || st.Mode().Perm() != 0600 {
					t.Fatal("import file access mode")
				}
			}
			st, err := os.Stat(path)
			if err != nil || st.Mode().Perm() != 0700 {
				t.Fatal("import directory access mode")
			}
			records := bookRecords(t, path, "HTTP", func() *types.HTTP { return new(types.HTTP) })
			want := "10.1.2.3"
			if sensor == "outside" {
				want = "192.0.2.254"
			}
			if len(records) != 1 || records[0].SrcIP != want || records[0].URL != "/two-sensor-marker" {
				t.Fatal("imported sensor observations conflated")
			}
			if os.Getenv("NETCAP_BOOK_EXPORT_DIR") != "" {
				t.Cleanup(func() {
					if !t.Failed() {
						exportBookCase(t, inputs[sensor], path, 2, false)
					}
				})
			}
		})
		if _, err := ImportSensorOutput(ctx, bundles[sensor], store, scope); err == nil {
			t.Fatal("replay overwrote existing run")
		}
	}
	if filepath.Dir(imports["inside"]) == filepath.Dir(imports["outside"]) {
		t.Fatal("sensor namespaces are not separated")
	}
	tampered, err := SealSensorOutput(ctx, outputs["inside"], sensorTestStore(t), "inside", now, now.Add(time.Hour), keys["inside"])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tampered, "Connection.ncap"), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	failedStore := sensorTestStore(t)
	if _, err := ImportSensorOutput(ctx, tampered, failedStore, scope); err == nil {
		t.Fatal("tampered telemetry accepted")
	}
	entries, err := os.ReadDir(failedStore)
	if err != nil || len(entries) != 0 {
		t.Fatal("failed import left published or partial content")
	}
	if err := os.Remove(filepath.Join(tampered, "Connection.ncap")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outputs["inside"], "Connection.ncap"), filepath.Join(tampered, "Connection.ncap")); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportSensorOutput(ctx, tampered, failedStore, scope); err == nil {
		t.Fatal("symlink escaped bundle boundary")
	}
	m := bookJSON[SensorManifest](t, filepath.Join(tampered, sensorManifestName))
	m.Files[0].Path = "../escape"
	m.Signature = sensorSignature(m, keys["inside"])
	encoded, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tampered, sensorManifestName), encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportSensorOutput(ctx, tampered, failedStore, scope); err == nil || !strings.Contains(err.Error(), "inventory") {
		t.Fatalf("authorized signature bypassed path restriction: %v", err)
	}
	publicStore := filepath.Join(t.TempDir(), "public")
	if err := os.Mkdir(publicStore, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportSensorOutput(ctx, bundles["inside"], publicStore, scope); err == nil {
		t.Fatal("world-readable receiving store accepted")
	}
	insideOnly.Now = now.Add(2 * time.Hour)
	removed, err := PruneSensorImports(ctx, store, insideOnly)
	if err != nil || len(removed) != 1 {
		t.Fatalf("retention prune: %v %v", removed, err)
	}
	if _, err := os.Stat(imports["inside"]); !os.IsNotExist(err) {
		t.Fatal("expired authorized run retained")
	}
	if _, err := os.Stat(imports["outside"]); err != nil {
		t.Fatal("out-of-scope retention deletion")
	}
	outsideOnly := scope
	outsideOnly.Now = now.Add(2 * time.Hour)
	outsideOnly.SensorKeys = map[string][]byte{"outside": keys["outside"]}
	removed, err = PruneSensorImports(ctx, store, outsideOnly)
	if err != nil || len(removed) != 1 {
		t.Fatal("second authorized retention prune failed")
	}
}
