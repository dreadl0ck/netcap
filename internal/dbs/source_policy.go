package dbs

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/dreadl0ck/netcap/internal/vulndb"
)

type SourcePolicy struct {
	Format                string       `json:"format"`
	ExpiresAt             int64        `json:"expires_at"`
	Rules                 []SourceRule `json:"rules"`
	MinimumNVDCount       int          `json:"minimum_nvd_count"`
	MaximumCurrentFeedAge int64        `json:"max_current_feed_age_seconds"`
}

type SourceRule struct {
	Evidence       SourceEvidence `json:"evidence"`
	Files          []string       `json:"files"`
	PinnedRevision string         `json:"pinned_revision,omitempty"`
}

// ApproveCandidate evaluates operator-reviewed policies, never inferred grants.
// The resulting record states automation as its reviewer and binds exact outputs.
func ApproveCandidate(dir, policyPath, policyPin, registryPath string, previousCount int) error {
	b, err := readRegularBytes(policyPath, 16<<20)
	if err != nil {
		return err
	}
	if digest(b) != policyPin {
		return fmt.Errorf("source policy pin mismatch")
	}
	var policy SourcePolicy
	if err := decodeJSON(b, &policy); err != nil {
		return err
	}
	if policy.Format != "netcap-source-policy/v1" || policy.ExpiresAt <= time.Now().Unix() || policy.MinimumNVDCount < 1 {
		return fmt.Errorf("invalid or expired source policy")
	}
	if policy.MaximumCurrentFeedAge <= 0 || policy.MaximumCurrentFeedAge > 72*3600 {
		return fmt.Errorf("invalid NVD source-age policy")
	}
	var candidate Candidate
	if err := readJSON(filepath.Join(dir, CandidateFile), &candidate); err != nil {
		return err
	}
	if err := validateReleaseData(dir); err != nil {
		return err
	}
	db, err := vulndb.Open(filepath.Join(dir, "netcap.sqlite"))
	if err != nil {
		return err
	}
	meta, err := db.Meta()
	db.Close()
	if err != nil {
		return err
	}
	count, err := strconv.Atoi(meta["nvd_count"])
	if err != nil || count < policy.MinimumNVDCount || count < previousCount*95/100 {
		return fmt.Errorf("NVD count below policy baseline or decreased more than 5%%")
	}
	if meta["nvd_end_year"] != strconv.Itoa(time.Now().Year()) || meta["nvd_start_year"] != "2002" {
		return fmt.Errorf("incomplete annual NVD coverage")
	}
	var yearCounts map[string]int
	if err := json.Unmarshal([]byte(meta["nvd_year_counts"]), &yearCounts); err != nil {
		return fmt.Errorf("missing per-year NVD counts: %w", err)
	}
	if len(yearCounts) != time.Now().Year()-2002+1 {
		return fmt.Errorf("incomplete per-year counts")
	}
	for year := 2002; year <= time.Now().Year(); year++ {
		if yearCounts[strconv.Itoa(year)] <= 0 {
			return fmt.Errorf("empty required NVD year %d", year)
		}
	}
	rules := map[string]SourceRule{}
	for _, rule := range policy.Rules {
		if _, exists := rules[rule.Evidence.ID]; exists {
			return fmt.Errorf("duplicate policy source")
		}
		if err := validateEvidence(rule.Evidence); err != nil {
			return err
		}
		rules[rule.Evidence.ID] = rule
	}
	var reviews []ReviewedSource
	for i, observed := range candidate.Sources {
		if observed.ID == "nvd" {
			if err := validateNVDAcquisition(observed, yearCounts, policy.MaximumCurrentFeedAge); err != nil {
				return err
			}
		}
		rule, ok := rules[observed.ID]
		if !ok || observed.Origin != rule.Evidence.Origin || observed.Transformation != rule.Evidence.Transformation || (rule.PinnedRevision != "" && observed.Revision != rule.PinnedRevision) {
			return fmt.Errorf("source %s violates reviewed acquisition/transformation policy", observed.ID)
		}
		allowed := map[string]bool{}
		for _, f := range rule.Files {
			allowed[f] = true
		}
		var outputs []ReleaseFile
		for _, f := range candidate.Files {
			if f.Source != observed.ID {
				continue
			}
			if !allowed[f.Path] {
				return fmt.Errorf("unreviewed output %s", f.Path)
			}
			delete(allowed, f.Path)
			outputs = append(outputs, f)
		}
		if len(allowed) != 0 || len(outputs) == 0 {
			return fmt.Errorf("missing policy output for %s", observed.ID)
		}
		observed.GrantText, observed.GrantSHA256 = rule.Evidence.GrantText, rule.Evidence.GrantSHA256
		observed.GrantOrigin, observed.GrantRevision = rule.Evidence.GrantOrigin, rule.Evidence.GrantRevision
		observed.NoticeText = rule.Evidence.NoticeText
		candidate.Sources[i] = observed
		reviews = append(reviews, ReviewedSource{observed, outputs, "approved-for-publication", "source-policy-v1", policyPin, time.Now().UTC().Format(time.RFC3339)})
		delete(rules, observed.ID)
	}
	if len(rules) != 0 {
		return fmt.Errorf("required policy source missing")
	}
	if _, err := os.Stat(registryPath); err == nil {
		return fmt.Errorf("registry output already exists")
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := atomicJSON(filepath.Join(dir, CandidateFile), candidate); err != nil {
		return err
	}
	return atomicJSON(registryPath, reviews)
}
