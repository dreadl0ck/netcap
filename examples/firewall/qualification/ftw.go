//go:build coraza && http3

package main

import (
	"context"
	"crypto/sha1" // Git blob identity, not a security signature.
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

const ftwCommit = "aabf675fcfc5e489b424b844e6c9f1b39802df69"
const ftwFile = "tests/regression/tests/REQUEST-941-APPLICATION-ATTACK-XSS/941100.yaml"
const ftwBlob = "b0e54a727fa93d478347bcb40212b5a7949b05f8"
const ftwLicenseSHA256 = "97ea43d779892a3aced6dab9ff4815fff90b09f7d133b538de5e5d6c8e3e9f2f"

type ftwCorpus struct {
	RuleID int `yaml:"rule_id"`
	Tests  []struct {
		ID     int `yaml:"test_id"`
		Stages []struct {
			Input struct {
				Method  string            `yaml:"method"`
				URI     string            `yaml:"uri"`
				Headers map[string]string `yaml:"headers"`
			} `yaml:"input"`
		} `yaml:"stages"`
	} `yaml:"tests"`
}

func fetchCorpusFile(ctx context.Context, name string) ([]byte, error) {
	url := "https://raw.githubusercontent.com/coreruleset/coreruleset/" + ftwCommit + "/" + name
	r, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("corpus fetch %s: %d", name, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if len(b) > 65536 {
		return nil, fmt.Errorf("corpus file exceeds 64 KiB")
	}
	return b, err
}

// Only reviewed single-stage tests 2 and 4 are admitted. FTW log-rule assertions
// are not converted into claims of connector audit-rule visibility.
func runFTW(ctx context.Context, output string) error {
	b, err := fetchCorpusFile(ctx, ftwFile)
	if err != nil {
		return err
	}
	blob := sha1.New()
	_, _ = fmt.Fprintf(blob, "blob %d%c", len(b), 0)
	_, _ = blob.Write(b)
	if hex.EncodeToString(blob.Sum(nil)) != ftwBlob {
		return fmt.Errorf("immutable FTW blob mismatch")
	}
	license, err := fetchCorpusFile(ctx, "LICENSE")
	if err != nil {
		return err
	}
	licenseHash := sha256.Sum256(license)
	if hex.EncodeToString(licenseHash[:]) != ftwLicenseSHA256 {
		return fmt.Errorf("immutable Apache-2.0 license hash mismatch")
	}
	if err = os.WriteFile(filepath.Join(output, "CRS-LICENSE"), license, 0600); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(output, "941100.yaml"), b, 0600); err != nil {
		return err
	}
	var corpus ftwCorpus
	if err = yaml.Unmarshal(b, &corpus); err != nil {
		return err
	}
	if corpus.RuleID != 941100 || len(corpus.Tests) != 6 {
		return fmt.Errorf("reviewed FTW shape changed")
	}
	var rows []map[string]any
	passed := true
	for _, proto := range []int{1, 2, 3} {
		p, err := newProfile(ctx, 0, true, proto)
		if err != nil {
			return err
		}
		func() {
			defer p.Close()
			for _, tc := range corpus.Tests {
				if tc.ID != 2 && tc.ID != 4 {
					continue
				}
				if len(tc.Stages) != 1 || tc.Stages[0].Input.Method != "GET" {
					passed = false
					continue
				}
				in := tc.Stages[0].Input
				r, e := http.NewRequestWithContext(ctx, "GET", p.URL+in.URI, nil)
				if e != nil {
					passed = false
					continue
				}
				for k, v := range in.Headers {
					if k == "Host" {
						r.Host = v
					} else {
						r.Header.Set(k, v)
					}
				}
				before := p.Ledger.Requests.Load()
				resp, e := p.Client.Do(r)
				status, actual := 0, 0
				if e == nil {
					status, actual = resp.StatusCode, resp.ProtoMajor
					_, e = io.Copy(io.Discard, io.LimitReader(resp.Body, 65537))
					_ = resp.Body.Close()
				}
				want, delta, split := 403, uint64(0), "attack-control"
				if tc.ID == 4 {
					want, delta, split = 200, 1, "withheld-benign"
				}
				ok := e == nil && status == want && actual == proto && p.Ledger.Requests.Load()-before == delta
				passed = passed && ok
				rows = append(rows, map[string]any{"profile": p.Name, "test_id": tc.ID, "split": split, "status": status, "expected_status": want, "protocol": actual, "origin_request_delta": p.Ledger.Requests.Load() - before, "accepted": ok, "error": fmt.Sprint(e)})
			}
		}()
	}
	hash := sha256.Sum256(b)
	report := map[string]any{"passed": passed, "upstream_commit": ftwCommit, "upstream_file": ftwFile, "git_blob": ftwBlob, "sha256": hex.EncodeToString(hash[:]), "license": "Apache-2.0; CRS-LICENSE stored with downloaded source", "attribution": "OWASP CRS project; fixture authors csanders-git, Walter Hop, azurit", "reviewed_supported_ids": []int{2, 4}, "excluded_ids": []int{1, 3, 5, 6}, "scope": "single-stage GET wire/status and origin reach; no FTW log-rule-ID equivalence claim; no policy tuning", "results": rows}
	report["license_sha256"] = ftwLicenseSHA256
	report["rights_check"] = "exact pinned Apache-2.0 license verified before execution"
	if err = atomicJSON(filepath.Join(output, "ftw.json"), report); err != nil {
		return err
	}
	if !passed {
		return fmt.Errorf("reviewed FTW subset failed")
	}
	return nil
}
