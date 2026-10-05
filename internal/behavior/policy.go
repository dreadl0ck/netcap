package behavior

import (
	"encoding/json"
	"errors"
	"io"
	"os"
)

func LoadPolicy(path string) (Policy, error) {
	file, err := os.Open(path)
	if err != nil {
		return Policy{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Policy{}, err
	}
	if info.Size() > 64<<10 {
		return Policy{}, errors.New("policy JSON exceeds 64 KiB")
	}
	policy := DefaultPolicy()
	decoder := json.NewDecoder(io.LimitReader(file, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return Policy{}, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return Policy{}, errors.New("expected one bounded policy JSON object")
	}
	return policy, validatePolicy(policy)
}
