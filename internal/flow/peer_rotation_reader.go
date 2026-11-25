package flow

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/dreadl0ck/netcap/internal/artifactio"
	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

type PeerRotationResult struct {
	AuditGeneration string              `json:"auditGeneration"`
	Candidates      []RotationCandidate `json:"candidates"`
}

// ReadPeerRotation searches one finalized capture without emitting alerts.
func ReadPeerRotation(ctx context.Context, dir string) (PeerRotationResult, error) {
	var result PeerRotationResult
	marker, err := artifactio.Read(ctx, dir, evidence.AuditReadyFile, 4096)
	if err != nil {
		return result, fmt.Errorf("peer rotation requires finalized capture output: %w", err)
	}
	var ready struct {
		Version int    `json:"version"`
		RunID   string `json:"runId"`
	}
	if err := json.Unmarshal(marker, &ready); err != nil || ready.Version != 1 || ready.RunID == "" {
		return result, fmt.Errorf("invalid audit output ready marker")
	}
	var index rotationIndex
	generation, err := scanRotationTrack(ctx, dir, ready.RunID, "", types.Type_NC_Connection, rotationRowLimit, new(types.Connection), index.add)
	if err != nil {
		return result, err
	}
	failures, witnesses := index.prepare()
	if len(witnesses) > 0 {
		_, err = scanRotationTrack(ctx, dir, ready.RunID, generation, types.Type_NC_TCP, 3_000_000, new(types.TCP), func(packet *types.TCP, ordinal int) error {
			index.observePayload(witnesses, packet, ordinal)
			return nil
		})
		if err != nil {
			return result, err
		}
	}
	result.Candidates, err = index.candidates(ctx, failures, witnesses)
	result.AuditGeneration = generation
	return result, err
}

func scanRotationTrack[T proto.Message](ctx context.Context, dir, runID, generation string, typ types.Type, limit int, row T, visit func(T, int) error) (string, error) {
	track := strings.TrimPrefix(typ.String(), "NC_")
	stage, snapshot, file, err := evidence.OpenAuditStageContext(ctx, dir, runID, track, generation)
	if err != nil {
		return "", fmt.Errorf("%s audit: %w", track, err)
	}
	if file != nil {
		defer file.Close()
	}
	if stage.Coverage != "complete" {
		return "", fmt.Errorf("%s audit coverage is %s", track, stage.Coverage)
	}
	if stage.Records > int64(limit) {
		return "", fmt.Errorf("%s audit exceeds the %d record limit", track, limit)
	}
	if file == nil {
		return snapshot.Generation, nil
	}
	var expected string
	for _, sealed := range stage.Files {
		if sealed.Name == filepath.Base(file.Name()) {
			expected = sealed.SHA256
			break
		}
	}
	digest := sha256.New()
	var input io.Reader = io.TeeReader(file, digest)
	if strings.HasSuffix(file.Name(), ".gz") {
		gz, err := gzip.NewReader(input)
		if err != nil {
			return "", err
		}
		defer gz.Close()
		input = gz
	}
	reader := delimited.NewReaderWithLimit(&decodedBudgetReader{input: input, remaining: 256 << 20}, 4<<20)
	var header types.Header
	if err := reader.NextProto(&header); err != nil {
		return "", fmt.Errorf("%s audit header: %w", track, err)
	}
	if header.Type != typ {
		return "", fmt.Errorf("expected %s audit, got %s", typ, header.Type)
	}
	ordinal := 0
	for ; ; ordinal++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		row.Reset()
		if err := reader.NextProto(row); err == io.EOF {
			break
		} else if err != nil {
			return "", fmt.Errorf("%s audit ordinal %d: %w", track, ordinal, err)
		}
		if ordinal >= limit || int64(ordinal) >= stage.Records {
			return "", fmt.Errorf("%s audit exceeded sealed record count or scan budget", track)
		}
		if err := visit(row, ordinal); err != nil {
			return "", err
		}
	}
	if int64(ordinal) != stage.Records || hex.EncodeToString(digest.Sum(nil)) != expected {
		return "", fmt.Errorf("%s audit changed or differs from its sealed record count", track)
	}
	return snapshot.Generation, nil
}
