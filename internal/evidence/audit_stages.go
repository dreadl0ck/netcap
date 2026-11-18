package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/dreadl0ck/netcap/types"
)

const AuditStagesFile = "audit-output-stages.json"

type SealedAuditFile struct {
	Name   string `json:"name"`
	Size   int64  `json:"size,string"`
	SHA256 string `json:"sha256"`
}

type AuditStage struct {
	Type     string            `json:"type"`
	Stage    string            `json:"stage"`
	State    string            `json:"state"`
	Coverage string            `json:"coverage"`
	Reason   string            `json:"reason,omitempty"`
	Records  int64             `json:"records,string"`
	Files    []SealedAuditFile `json:"files"`
}

type AuditStages struct {
	Version     int          `json:"version"`
	RunID       string       `json:"runId"`
	Generation  string       `json:"generation"`
	InputSHA256 string       `json:"inputSHA256,omitempty"`
	Stages      []AuditStage `json:"stages"`
}

func validAuditType(name string) bool { _, ok := types.Type_value["NC_"+name]; return ok && name != "" }

func validAuditFile(name, recordType string) bool {
	if recordType == "VRRPv2" && strings.HasPrefix(name, "VRRP.") {
		recordType = "VRRP"
	}
	for _, suffix := range []string{".ncap", ".ncap.gz", ".json", ".json.gz", ".csv", ".csv.gz"} {
		if name == recordType+suffix {
			return true
		}
	}
	return false
}

func auditStageGeneration(stages AuditStages) (string, error) {
	stages.Generation = ""
	data, err := json.Marshal(stages)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

type auditSealReader struct {
	ctx  context.Context
	file *os.File
}

func (r auditSealReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.file.Read(p)
}

func auditFileSeal(ctx context.Context, root *os.Root, name string, expected *SealedAuditFile) (result SealedAuditFile, resultErr error) {
	if name == "" || strings.ContainsAny(name, "/\\") || name == "." || name == ".." {
		return result, fmt.Errorf("invalid audit file name")
	}
	pathInfo, err := root.Lstat(name)
	if err != nil {
		return result, err
	}
	if !pathInfo.Mode().IsRegular() {
		return result, fmt.Errorf("audit output is not a regular file")
	}
	file, err := root.Open(name)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	before, err := file.Stat()
	if err != nil {
		return result, err
	}
	if !os.SameFile(pathInfo, before) {
		return result, fmt.Errorf("audit output changed while opening")
	}
	if expected != nil && before.Size() != expected.Size {
		return result, fmt.Errorf("sealed audit output changed: size mismatch")
	}
	hash := sha256.New()
	reader := auditSealReader{ctx: ctx, file: file}
	n, err := io.CopyN(hash, reader, before.Size())
	if err != nil {
		return result, err
	}
	var extra [1]byte
	if n, err := io.ReadFull(reader, extra[:]); n != 0 {
		return result, fmt.Errorf("audit output grew during sealing")
	} else if err != io.EOF {
		return result, err
	}
	after, err := file.Stat()
	if err != nil {
		return result, err
	}
	if n != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return result, fmt.Errorf("audit output changed during sealing")
	}
	return SealedAuditFile{Name: name, Size: n, SHA256: hex.EncodeToString(hash.Sum(nil))}, nil
}

// SealAuditStages publishes immutable per-type writer results after every producer stops.
func (c *Capture) SealAuditStages(stages []AuditStage) (resultErr error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		return fmt.Errorf("cannot seal stages while capture is running")
	}
	defer func() {
		if resultErr != nil {
			c.storageError = errors.Join(c.storageError, resultErr)
			c.manifest.Status = "error"
			c.manifest.Error = c.storageError.Error()
			resultErr = errors.Join(resultErr, c.checkpoint())
		}
	}()
	root, err := os.OpenRoot(c.directory)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	result := AuditStages{Version: 1, RunID: c.manifest.RunID, InputSHA256: c.manifest.InputSHA256, Stages: stages}
	if len(stages) > 512 {
		return fmt.Errorf("audit stage inventory exceeds 512 entries")
	}
	slices.SortFunc(result.Stages, func(a, b AuditStage) int { return strings.Compare(a.Type, b.Type) })
	last := ""
	for index := range result.Stages {
		stage := &result.Stages[index]
		if !validAuditType(stage.Type) || stage.Type == last || stage.Records < 0 {
			return fmt.Errorf("invalid or duplicate audit stage")
		}
		last = stage.Type
		if stage.Stage != "packet" && stage.Stage != "aggregate" && stage.Stage != "application" {
			return fmt.Errorf("invalid audit stage class")
		}
		if stage.State != "sealed" && stage.State != "failed" && stage.State != "unavailable" {
			return fmt.Errorf("invalid audit stage state")
		}
		if stage.Files == nil {
			stage.Files = []SealedAuditFile{}
		}
		if stage.State != "sealed" {
			stage.Files = []SealedAuditFile{}
			continue
		}
		if stage.Coverage != "complete" && stage.Coverage != "partial" {
			return fmt.Errorf("invalid sealed coverage")
		}
		if stage.Records > 0 && len(stage.Files) == 0 {
			return fmt.Errorf("nonempty sealed stage lacks an audit file")
		}
		seen := map[string]bool{}
		for i := range stage.Files {
			if !validAuditFile(stage.Files[i].Name, stage.Type) || seen[stage.Files[i].Name] {
				return fmt.Errorf("invalid or duplicate audit stage file %q for %s", stage.Files[i].Name, stage.Type)
			}
			seen[stage.Files[i].Name] = true
			sealed, err := auditFileSeal(context.Background(), root, stage.Files[i].Name, nil)
			if err != nil {
				return err
			}
			stage.Files[i] = sealed
		}
		slices.SortFunc(stage.Files, func(a, b SealedAuditFile) int { return strings.Compare(a.Name, b.Name) })
	}
	result.Generation, err = auditStageGeneration(result)
	if err != nil {
		return err
	}
	file, err := root.OpenFile(".audit-output-stages.tmp", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(".audit-output-stages.tmp")
	writeErr := json.NewEncoder(file).Encode(result)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	if _, err := root.Lstat(AuditStagesFile); !os.IsNotExist(err) {
		return fmt.Errorf("audit stages already exist or are inaccessible")
	}
	if err := root.Rename(".audit-output-stages.tmp", AuditStagesFile); err != nil {
		return err
	}
	c.manifest.AuditStagesGeneration = result.Generation
	return c.checkpoint()
}

func ReadAuditStage(directory, runID, recordType, generation string) (stage AuditStage, snapshot AuditStages, resultErr error) {
	return ReadAuditStageContext(context.Background(), directory, runID, recordType, generation)
}

func ReadAuditStageContext(ctx context.Context, directory, runID, recordType, generation string) (stage AuditStage, snapshot AuditStages, resultErr error) {
	if err := ctx.Err(); err != nil {
		return stage, snapshot, err
	}
	if !validAuditType(recordType) || runID == "" {
		return stage, snapshot, fmt.Errorf("explicit run and canonical audit type required")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return stage, snapshot, err
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	file, err := root.Open(AuditStagesFile)
	if err != nil {
		return stage, snapshot, err
	}
	info, err := file.Stat()
	if err != nil || info.Size() > 1<<20 {
		_ = file.Close()
		return stage, snapshot, fmt.Errorf("audit stage inventory exceeds readable limits")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&snapshot)
	if err == nil {
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			err = fmt.Errorf("invalid trailing audit stage data")
		}
	}
	closeErr := file.Close()
	if err = errors.Join(err, closeErr); err != nil {
		return stage, snapshot, err
	}
	expected, err := auditStageGeneration(snapshot)
	if err != nil {
		return stage, snapshot, err
	}
	if snapshot.Version != 1 || snapshot.RunID != runID || snapshot.Generation != expected || generation != "" && generation != snapshot.Generation {
		return stage, snapshot, fmt.Errorf("audit stage generation is stale or invalid")
	}
	if len(snapshot.Stages) > 512 {
		return stage, snapshot, fmt.Errorf("audit stage inventory exceeds 512 entries")
	}
	seenTypes := map[string]bool{}
	for _, candidate := range snapshot.Stages {
		if !validAuditType(candidate.Type) || seenTypes[candidate.Type] || candidate.Records < 0 {
			return stage, snapshot, fmt.Errorf("invalid or duplicate audit stage")
		}
		seenTypes[candidate.Type] = true
	}
	manifestFile, err := root.Open("capture-manifest.json")
	if err != nil {
		return stage, snapshot, err
	}
	var manifest CaptureManifest
	err = json.NewDecoder(io.LimitReader(manifestFile, 4<<20)).Decode(&manifest)
	err = errors.Join(err, manifestFile.Close())
	if err != nil {
		return stage, snapshot, err
	}
	if manifest.RunID != runID || manifest.InputSHA256 != snapshot.InputSHA256 || manifest.AuditStagesGeneration != snapshot.Generation {
		return stage, snapshot, fmt.Errorf("audit stage inventory does not match capture generation")
	}
	for _, candidate := range snapshot.Stages {
		if candidate.Type == recordType {
			if candidate.State != "sealed" || candidate.Coverage != "complete" && candidate.Coverage != "partial" {
				return stage, snapshot, fmt.Errorf("requested audit stage is not sealed")
			}
			if candidate.Records > 0 && len(candidate.Files) == 0 {
				return stage, snapshot, fmt.Errorf("sealed stage lacks output files")
			}
			for _, suffix := range []string{".ncap", ".ncap.gz", ".json", ".json.gz", ".csv", ".csv.gz"} {
				name := recordType + suffix
				found := false
				for _, file := range candidate.Files {
					found = found || file.Name == name
				}
				if !found {
					if _, err := root.Lstat(name); !os.IsNotExist(err) {
						return stage, snapshot, fmt.Errorf("unsealed audit file exists for requested type")
					}
				}
			}
			if recordType == "VRRPv2" {
				for _, suffix := range []string{".ncap", ".ncap.gz"} {
					name := "VRRP" + suffix
					found := false
					for _, file := range candidate.Files {
						found = found || file.Name == name
					}
					if !found {
						if _, err := root.Lstat(name); !os.IsNotExist(err) {
							return stage, snapshot, fmt.Errorf("unsealed audit alias exists")
						}
					}
				}
			}
			seenFiles := map[string]bool{}
			for _, sealed := range candidate.Files {
				if !validAuditFile(sealed.Name, recordType) || seenFiles[sealed.Name] {
					return stage, snapshot, fmt.Errorf("invalid or duplicate sealed file")
				}
				seenFiles[sealed.Name] = true
				actual, err := auditFileSeal(ctx, root, sealed.Name, &sealed)
				if err != nil {
					return stage, snapshot, err
				}
				if actual != sealed {
					return stage, snapshot, fmt.Errorf("sealed audit output changed")
				}
			}
			return candidate, snapshot, nil
		}
	}
	return stage, snapshot, fmt.Errorf("requested audit stage is unavailable")
}
