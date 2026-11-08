package analyst

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/dreadl0ck/netcap/internal/artifactio"
)

const ReviewedLogFile = "analyst-reviewed-log.json"

type SafeLogLine struct {
	Ordinal int      `json:"ordinal"`
	SHA256  string   `json:"sha256"`
	Classes []string `json:"classes"`
}
type LogReview struct {
	Version          int           `json:"version"`
	Binding          Binding       `json:"binding"`
	File             string        `json:"file"`
	FileSHA256       string        `json:"fileSHA256"`
	Start            int           `json:"start"`
	End              int           `json:"end"`
	Lines            []SafeLogLine `json:"lines"`
	ProjectionSHA256 string        `json:"projectionSHA256"`
	State            string        `json:"state"`
}

func PreviewLog(ctx context.Context, dir string, binding Binding, name string, start, end int) (LogReview, error) {
	result := LogReview{Version: 1, Binding: binding, File: name, Start: start, End: end, Lines: []SafeLogLine{}, State: "preview"}
	if name != filepath.Base(name) || !strings.HasSuffix(name, ".log") || start < 1 || end < start || end-start >= 200 {
		return result, fmt.Errorf("select a local .log and 1–200 explicit lines")
	}
	if err := CheckDiagnostic(ctx, dir, binding); err != nil {
		return result, err
	}
	data, err := artifactio.Read(ctx, dir, name, 4<<20)
	if err != nil {
		return result, err
	}
	result.FileSHA256 = Digest(data)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), (4<<20)+1)
	ordinal := 0
	for scanner.Scan() {
		ordinal++
		if ordinal < start {
			continue
		}
		if ordinal > end {
			break
		}
		if err := ctx.Err(); err != nil {
			return result, err
		}
		line := strings.ToLower(scanner.Text())
		classes := []string{}
		for _, class := range []string{"error", "warning", "panic", "timeout", "cancel", "failed", "completed"} {
			if strings.Contains(line, class) {
				classes = append(classes, class)
			}
		}
		result.Lines = append(result.Lines, SafeLogLine{ordinal, Digest(scanner.Bytes()), classes})
		if ordinal == end {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return result, err
	}
	if ordinal < end {
		return result, fmt.Errorf("selected log lines unavailable")
	}
	projected, _ := json.Marshal(result)
	result.ProjectionSHA256 = Digest(projected)
	return result, CheckDiagnostic(ctx, dir, binding)
}

func ApproveLog(ctx context.Context, dir string, review LogReview) error {
	storeMu.Lock()
	defer storeMu.Unlock()
	current, err := PreviewLog(ctx, dir, review.Binding, review.File, review.Start, review.End)
	if err != nil {
		return err
	}
	if current.ProjectionSHA256 != review.ProjectionSHA256 || current.FileSHA256 != review.FileSHA256 {
		return ErrStale
	}
	// Never persist the caller's arbitrary line content or review fields.
	current.State = "reviewed"
	data, err := json.Marshal(current)
	if err != nil {
		return err
	}
	return AtomicJSON(ctx, dir, ReviewedLogFile, data, func() error {
		latest, e := PreviewLog(ctx, dir, review.Binding, review.File, review.Start, review.End)
		if e != nil {
			return e
		}
		if latest.ProjectionSHA256 != review.ProjectionSHA256 {
			return ErrStale
		}
		return nil
	})
}

func ReviewedLog(ctx context.Context, dir string, binding Binding) (LogReview, error) {
	var review LogReview
	data, err := artifactio.Read(ctx, dir, ReviewedLogFile, 256<<10)
	if err != nil {
		return review, err
	}
	if err = json.Unmarshal(data, &review); err != nil {
		return review, err
	}
	if review.Version != 1 || review.Binding != binding || review.State != "reviewed" {
		return review, ErrStale
	}
	current, err := PreviewLog(ctx, dir, binding, review.File, review.Start, review.End)
	if err != nil {
		return review, err
	}
	if current.ProjectionSHA256 != review.ProjectionSHA256 || current.FileSHA256 != review.FileSHA256 {
		return review, ErrStale
	}
	current.State = "reviewed"
	return current, nil
}
