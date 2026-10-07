package collector

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/internal/evidence"
)

const sensorManifestName = "sensor-bundle.json"
const maxSensorBytes int64 = 1 << 30

var sensorComponent = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

type SensorFile struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes,string"`
	SHA256 string `json:"sha256"`
}
type SensorManifest struct {
	Version     int          `json:"version"`
	SensorID    string       `json:"sensorId"`
	RunID       string       `json:"runId"`
	InputSHA256 string       `json:"inputSHA256"`
	CreatedNs   int64        `json:"createdNs,string"`
	ExpiresNs   int64        `json:"expiresNs,string"`
	Files       []SensorFile `json:"files"`
	Signature   string       `json:"hmacSHA256"`
}

// Scope is supplied by the receiving service, never decoded from an upload.
// SensorKeys proves shared-key possession, not endpoint or user authentication.
type SensorImportScope struct {
	SensorKeys   map[string][]byte
	Now          time.Time
	MaxBytes     int64
	MaxRetention time.Duration
}

func sensorSignature(m SensorManifest, key []byte) string {
	m.Signature = ""
	b, _ := json.Marshal(m)
	mac := hmac.New(sha256.New, key)
	mac.Write(b)
	return hex.EncodeToString(mac.Sum(nil))
}

func privateSensorStore(path string) (*os.Root, error) {
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("sensor store must be a private directory")
	}
	return os.OpenRoot(path)
}

type sensorContextReader struct {
	context.Context
	io.Reader
}

func (r sensorContextReader) Read(p []byte) (int, error) {
	if err := r.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(p)
}

func sensorRead(root *os.Root, path string) (*os.File, error) {
	st, err := root.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("sensor file is not regular: %s", path)
	}
	f, err := root.Open(path)
	if err != nil {
		return nil, err
	}
	st, err = f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("sensor file changed: %s", path)
	}
	return f, nil
}

func sensorCopy(ctx context.Context, src, dst *os.Root, path, target string, limit int64) (SensorFile, error) {
	var result SensorFile
	in, err := sensorRead(src, path)
	if err != nil {
		return result, err
	}
	defer in.Close()
	if err := dst.MkdirAll(filepath.Dir(target), 0700); err != nil {
		return result, err
	}
	out, err := dst.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return result, err
	}
	defer out.Close()
	digest := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, digest), io.LimitReader(sensorContextReader{ctx, in}, limit+1))
	if err != nil {
		return result, err
	}
	if n > limit {
		return result, fmt.Errorf("sensor byte budget exceeded")
	}
	if err := out.Sync(); err != nil {
		return result, err
	}
	return SensorFile{path, n, hex.EncodeToString(digest.Sum(nil))}, nil
}

func sensorStage(root *os.Root) (string, error) {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", err
	}
	name := fmt.Sprintf(".pending-%x", token)
	return name, root.Mkdir(name, 0700)
}

func publishSensor(root *os.Root, stage string, m SensorManifest) (string, error) {
	if err := root.MkdirAll(m.SensorID, 0700); err != nil {
		return "", err
	}
	target := filepath.Join(m.SensorID, m.RunID)
	lock, err := root.OpenFile(target+".lock", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", fmt.Errorf("sensor run import already in progress: %w", err)
	}
	lock.Close()
	defer root.Remove(target + ".lock")
	if _, err := root.Lstat(target); !os.IsNotExist(err) {
		return "", fmt.Errorf("sensor run already exists or is inaccessible")
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	if err := root.WriteFile(filepath.Join(stage, sensorManifestName), b, 0600); err != nil {
		return "", err
	}
	if err := root.Rename(stage, target); err != nil {
		return "", err
	}
	return target, nil
}

// SealSensorOutput snapshots a completed local collector output into a signed,
// private bundle. The transport to the receiving service is caller-owned.
func SealSensorOutput(ctx context.Context, output, store, sensorID string, now, expires time.Time, key []byte) (string, error) {
	if !sensorComponent.MatchString(sensorID) || len(key) < 32 || now.IsZero() || !expires.After(now) || expires.Sub(now) > 30*24*time.Hour {
		return "", fmt.Errorf("invalid sensor identity, key or retention")
	}
	source, err := os.OpenRoot(output)
	if err != nil {
		return "", err
	}
	defer source.Close()
	data, err := readSensorMetadata(source, "capture-manifest.json")
	if err != nil {
		return "", err
	}
	var capture evidence.CaptureManifest
	if err := json.Unmarshal(data, &capture); err != nil {
		return "", err
	}
	if capture.Status != "done" || !sensorComponent.MatchString(capture.RunID) || len(capture.InputSHA256) != 64 {
		return "", fmt.Errorf("sensor capture must be finalized file evidence")
	}
	dest, err := privateSensorStore(store)
	if err != nil {
		return "", err
	}
	defer dest.Close()
	stage, err := sensorStage(dest)
	if err != nil {
		return "", err
	}
	defer dest.RemoveAll(stage)
	m := SensorManifest{Version: 1, SensorID: sensorID, RunID: capture.RunID, InputSHA256: capture.InputSHA256, CreatedNs: now.UnixNano(), ExpiresNs: expires.UnixNano()}
	var total int64
	err = fs.WalkDir(source.FS(), ".", func(path string, e fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if e.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".log") {
			return nil
		}
		if path == sensorManifestName || len(m.Files) >= 4096 || len(path) > 512 {
			return fmt.Errorf("invalid sensor output layout or file budget")
		}
		file, err := sensorCopy(ctx, source, dest, path, filepath.Join(stage, path), maxSensorBytes-total)
		if err != nil {
			return err
		}
		total += file.Bytes
		m.Files = append(m.Files, file)
		return nil
	})
	if err != nil {
		return "", err
	}
	// The staged manifest must still identify the run whose files were copied.
	if err := checkSensorCapture(dest, stage, m); err != nil {
		return "", err
	}
	m.Signature = sensorSignature(m, key)
	rel, err := publishSensor(dest, stage, m)
	return filepath.Join(store, rel), err
}

func loadSensorManifest(root *os.Root, path string) (SensorManifest, error) {
	var m SensorManifest
	b, err := readSensorMetadata(root, path)
	if err != nil {
		return m, err
	}
	err = json.Unmarshal(b, &m)
	return m, err
}

func readSensorMetadata(root *os.Root, path string) ([]byte, error) {
	f, err := sensorRead(root, path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 8<<20+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 8<<20 {
		return nil, fmt.Errorf("sensor manifest too large")
	}
	return b, nil
}

func authorizeSensor(m SensorManifest, scope SensorImportScope) error {
	key, ok := scope.SensorKeys[m.SensorID]
	if !ok || len(key) < 32 || m.Version != 1 || !sensorComponent.MatchString(m.SensorID) || !sensorComponent.MatchString(m.RunID) {
		return fmt.Errorf("sensor is outside authorized scope")
	}
	actual, err := hex.DecodeString(m.Signature)
	if err != nil {
		return fmt.Errorf("invalid sensor signature")
	}
	expected, _ := hex.DecodeString(sensorSignature(m, key))
	if !hmac.Equal(actual, expected) {
		return fmt.Errorf("sensor signature mismatch")
	}
	if scope.Now.IsZero() || scope.MaxBytes <= 0 || scope.MaxBytes > maxSensorBytes || scope.MaxRetention <= 0 || scope.MaxRetention > 30*24*time.Hour {
		return fmt.Errorf("invalid receiving scope")
	}
	if m.CreatedNs <= 0 || m.CreatedNs > scope.Now.UnixNano() || m.ExpiresNs <= m.CreatedNs || m.ExpiresNs-m.CreatedNs > int64(scope.MaxRetention) {
		return fmt.Errorf("sensor retention outside receiving policy")
	}
	return nil
}

func checkSensorCapture(root *os.Root, base string, m SensorManifest) error {
	b, err := readSensorMetadata(root, filepath.Join(base, "capture-manifest.json"))
	if err != nil {
		return err
	}
	var c evidence.CaptureManifest
	if err := json.Unmarshal(b, &c); err != nil {
		return err
	}
	if c.Status != "done" || c.RunID != m.RunID || c.InputSHA256 != m.InputSHA256 {
		return fmt.Errorf("sensor/capture identity mismatch")
	}
	return nil
}

// ImportSensorOutput verifies scope, signature, expiry and every file before an
// atomic publication. Existing sensor/run identities are never overwritten.
func ImportSensorOutput(ctx context.Context, bundle, store string, scope SensorImportScope) (string, error) {
	source, err := os.OpenRoot(bundle)
	if err != nil {
		return "", err
	}
	defer source.Close()
	m, err := loadSensorManifest(source, sensorManifestName)
	if err != nil {
		return "", err
	}
	if err := authorizeSensor(m, scope); err != nil {
		return "", err
	}
	if m.ExpiresNs <= scope.Now.UnixNano() {
		return "", fmt.Errorf("sensor bundle expired")
	}
	if len(m.Files) == 0 || len(m.Files) > 4096 {
		return "", fmt.Errorf("invalid sensor file count")
	}
	seen := map[string]bool{}
	var total int64
	for _, f := range m.Files {
		if !filepath.IsLocal(f.Path) || filepath.Clean(f.Path) != f.Path || len(f.Path) > 512 || f.Path == sensorManifestName || seen[f.Path] || f.Bytes < 0 || f.Bytes > scope.MaxBytes-total || len(f.SHA256) != 64 {
			return "", fmt.Errorf("invalid sensor file inventory")
		}
		seen[f.Path] = true
		total += f.Bytes
	}
	if !seen["capture-manifest.json"] {
		return "", fmt.Errorf("sensor capture manifest missing")
	}
	dest, err := privateSensorStore(store)
	if err != nil {
		return "", err
	}
	defer dest.Close()
	stage, err := sensorStage(dest)
	if err != nil {
		return "", err
	}
	defer dest.RemoveAll(stage)
	for _, f := range m.Files {
		got, err := sensorCopy(ctx, source, dest, f.Path, filepath.Join(stage, f.Path), f.Bytes)
		if err != nil {
			return "", err
		}
		if got.Bytes != f.Bytes || got.SHA256 != f.SHA256 {
			return "", fmt.Errorf("sensor content hash mismatch: %s", f.Path)
		}
	}
	if err := checkSensorCapture(dest, stage, m); err != nil {
		return "", err
	}
	rel, err := publishSensor(dest, stage, m)
	return filepath.Join(store, rel), err
}

// PruneSensorImports removes only expired, signed runs belonging to the supplied
// scope. The service schedules this call; expiration alone does not delete bytes.
func PruneSensorImports(ctx context.Context, store string, scope SensorImportScope) ([]string, error) {
	root, err := privateSensorStore(store)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	var removed []string
	for sensor := range scope.SensorKeys {
		if !sensorComponent.MatchString(sensor) {
			return removed, fmt.Errorf("invalid sensor scope name")
		}
		dir, err := root.Open(sensor)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return removed, err
		}
		entries, err := dir.ReadDir(-1)
		dir.Close()
		if err != nil {
			return removed, err
		}
		for _, e := range entries {
			if err := ctx.Err(); err != nil {
				return removed, err
			}
			if !e.IsDir() {
				continue
			}
			path := filepath.Join(sensor, e.Name())
			m, err := loadSensorManifest(root, filepath.Join(path, sensorManifestName))
			if err != nil {
				return removed, err
			}
			if m.SensorID != sensor || m.RunID != e.Name() {
				return removed, fmt.Errorf("stored sensor identity mismatch")
			}
			if err := authorizeSensor(m, scope); err != nil {
				return removed, err
			}
			if m.ExpiresNs <= scope.Now.UnixNano() {
				if err := root.RemoveAll(path); err != nil {
					return removed, err
				}
				removed = append(removed, path)
			}
		}
	}
	return removed, nil
}
