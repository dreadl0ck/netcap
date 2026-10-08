package protocoltest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

type CorpusCase struct {
	ID     string `json:"id"`
	Input  []byte `json:"input"`
	SHA256 string `json:"sha256"`
}

type ByteCorpus struct {
	Version             int          `json:"version"`
	GenerationVersion   string       `json:"generationVersion"`
	TargetVersion       string       `json:"targetVersion"`
	ConfigurationSHA256 string       `json:"configurationSHA256"`
	Cases               []CorpusCase `json:"cases"`
}

func GenerateByteCorpus(seed []byte, maxCases, maxBytes int, target string) (ByteCorpus, error) {
	r := ByteCorpus{Version: 1, GenerationVersion: GenerationVersion, TargetVersion: target}
	if target == "" || len(target) > 1024 {
		return r, fmt.Errorf("target version required")
	}
	r.ConfigurationSHA256 = configHash(struct {
		Version            int
		Generator, Target  string
		Seed               []byte
		MaxCases, MaxBytes int
	}{1, GenerationVersion, target, seed, maxCases, maxBytes})
	var err error
	r.Cases, err = MutationCorpus(seed, maxCases, maxBytes)
	return r, err
}

// MutationCorpus is deterministic: control, truncations, then single-byte XORs.
// It deliberately preserves malformed lengths; it does not infer a grammar.
func MutationCorpus(seed []byte, maxCases, maxBytes int) ([]CorpusCase, error) {
	if len(seed) == 0 || len(seed) > 65536 || maxCases < 1 || maxCases > 10000 || maxBytes < 1 || maxBytes > 16<<20 {
		return nil, fmt.Errorf("invalid corpus bounds")
	}
	cases := []CorpusCase{}
	total := 0
	add := func(id string, b []byte) error {
		if len(cases) >= maxCases || len(b) > maxBytes-total {
			return fmt.Errorf("corpus budget exceeded")
		}
		sum := sha256.Sum256(b)
		cases = append(cases, CorpusCase{ID: id, Input: append([]byte{}, b...), SHA256: hex.EncodeToString(sum[:])})
		total += len(b)
		return nil
	}
	if err := add("control", seed); err != nil {
		return nil, err
	}
	for i := 0; i < len(seed); i++ {
		if err := add(fmt.Sprintf("truncate-%d", i), seed[:i]); err != nil {
			return nil, err
		}
	}
	for i := range seed {
		b := bytes.Clone(seed)
		b[i] ^= 255
		if err := add(fmt.Sprintf("xor-%d", i), b); err != nil {
			return nil, err
		}
	}
	return cases, nil
}

type Minimized struct {
	Original []byte `json:"original"`
	Input    []byte `json:"input"`
	Attempts int    `json:"attempts"`
	Complete bool   `json:"complete"`
}

// Minimize deletes bytes while an explicit failure oracle still reproduces.
// Oracle errors (including transport errors) are not classified as failures.
func Minimize(ctx context.Context, input []byte, maxAttempts int, oracle func(context.Context, []byte) (bool, error)) (Minimized, error) {
	r := Minimized{Original: bytes.Clone(input), Input: bytes.Clone(input)}
	if len(input) > 65536 || maxAttempts < 1 || maxAttempts > 10000 || oracle == nil {
		return r, fmt.Errorf("invalid minimization bounds")
	}
	check := func(b []byte) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if r.Attempts >= maxAttempts {
			return false, fmt.Errorf("minimization attempt budget exceeded")
		}
		r.Attempts++
		return oracle(ctx, bytes.Clone(b))
	}
	ok, err := check(r.Input)
	if err != nil {
		return r, err
	}
	if !ok {
		return r, fmt.Errorf("original failure does not reproduce")
	}
	for i := 0; i < len(r.Input); {
		candidate := append(bytes.Clone(r.Input[:i]), r.Input[i+1:]...)
		ok, err = check(candidate)
		if err != nil {
			return r, err
		}
		if ok {
			r.Input = candidate
			i = 0
		} else {
			i++
		}
	}
	r.Complete = true
	return r, nil
}

type TriageArtifact struct {
	InputGeneration     string `json:"inputGeneration"`
	Version             int    `json:"version"`
	GenerationVersion   string `json:"generationVersion"`
	ConfigurationSHA256 string `json:"configurationSHA256"`
	InputSHA256         string `json:"inputSHA256"`
	Kind                string `json:"kind"`
	TargetVersion       string `json:"targetVersion"`
	Reset               string `json:"reset"`
	Input               []byte `json:"input"`
	Evidence            []byte `json:"evidence"`
	EvidenceSHA256      string `json:"evidenceSHA256"`
	Classification      string `json:"classification"`
}

// ImportTriage retains external evidence verbatim without executing it or
// interpreting a stack, sanitizer report or process exit as proof of impact.
func ImportTriage(kind, version, reset string, input []byte, path string) (TriageArtifact, error) {
	return ImportGeneratedTriage(kind, version, reset, "external-unspecified", input, path)
}
func ImportGeneratedTriage(kind, version, reset, inputGeneration string, input []byte, path string) (TriageArtifact, error) {
	r := TriageArtifact{Version: 1, GenerationVersion: GenerationVersion, Kind: kind, TargetVersion: version, Reset: reset, Input: bytes.Clone(input), Classification: "external evidence; impact unverified"}
	r.InputGeneration = inputGeneration
	if inputGeneration == "" || len(inputGeneration) > 1024 {
		return r, fmt.Errorf("input generation/config version required")
	}
	if (kind != "stack" && kind != "sanitizer" && kind != "process" && kind != "impact" && kind != "routing" && kind != "socket-trace" && kind != "debugger" && kind != "decompiler" && kind != "reset") || version == "" || reset == "" || len(input) > 65536 {
		return r, fmt.Errorf("unsupported artifact kind or missing reproduction metadata")
	}
	b, err := boundedFile(path, 1<<20)
	if err != nil {
		return r, err
	}
	if len(b) == 0 {
		return r, fmt.Errorf("empty external evidence")
	}
	r.Evidence = b
	sum := sha256.Sum256(b)
	r.EvidenceSHA256 = hex.EncodeToString(sum[:])
	sum = sha256.Sum256(input)
	r.InputSHA256 = hex.EncodeToString(sum[:])
	r.ConfigurationSHA256 = configHash(struct {
		Version                                         int
		Generator, Kind, Target, Reset, Input, Evidence string
	}{1, GenerationVersion + ":" + inputGeneration, kind, version, reset, r.InputSHA256, r.EvidenceSHA256})
	return r, nil
}
