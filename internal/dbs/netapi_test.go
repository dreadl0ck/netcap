package dbs

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/resolvers"
)

func TestNetAPIPublicationPolicy(t *testing.T) {
	var policy SourcePolicy
	if err := readJSON("../../configs/dbs/source-policy.json", &policy); err != nil {
		t.Fatal(err)
	}
	for _, rule := range policy.Rules {
		if rule.Evidence.ID != "netapi" {
			continue
		}
		if err := validateEvidence(rule.Evidence); err != nil {
			t.Fatal(err)
		}
		if len(rule.Files) != 1 || CandidateFiles()[rule.Files[0]] != "netapi" || rule.PinnedRevision != "" {
			t.Fatal("NetAPI must permit reviewed daily CSV updates", rule)
		}
		for _, source := range sources {
			if source.name == rule.Files[0] && source.url == rule.Evidence.Origin {
				return
			}
		}
		t.Fatal("NetAPI acquisition missing")
	}
	t.Fatal("NetAPI clearance missing")
}

func TestNetAPILiveCSV(t *testing.T) {
	if os.Getenv("NETCAP_TEST_NETAPI_LIVE") != "1" {
		t.Skip("set NETCAP_TEST_NETAPI_LIVE=1 to validate the current upstream CSV")
	}
	client := &http.Client{Timeout: time.Minute}
	resp, err := client.Get("https://netapi.com/netapi_top1mln.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatal(resp.Status)
	}
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, resolvers.ManagedPopularityFile))
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(f, io.LimitReader(resp.Body, resolvers.MaxPopularityBytes+1))
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	_, stats, err := resolvers.LoadManagedDomainPopularityList(dir)
	if err != nil || stats.Rows != resolvers.MaxPopularityRows {
		t.Fatalf("NetAPI CSV: %+v: %v", stats, err)
	}
	t.Logf("NetAPI CSV: %+v", stats)
}
