package devicecatalog_test

import (
	"bytes"
	"testing"

	"github.com/dreadl0ck/netcap/internal/dbs"
	"github.com/dreadl0ck/netcap/internal/enrichment"
)

func TestRealUnsignedChannelCandidate(t *testing.T) {
	first, manifest, err := enrichment.Pack("channel")
	if err != nil {
		t.Fatal(err)
	}
	second, repeated, err := enrichment.Pack("channel")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) || manifest.ArchiveSHA256 != repeated.ArchiveSHA256 {
		t.Fatal("non-deterministic unsigned candidate")
	}
	if manifest.ArchiveSize == 0 || manifest.Sequence != 0 {
		t.Fatal("invalid unsigned candidate metadata")
	}
	t.Logf("unsigned DHCP/MAC archive sha256=%s bytes=%d", manifest.ArchiveSHA256, manifest.ArchiveSize)
}

func TestOptionalAnchorMatchesCore(t *testing.T) {
	root, err := dbs.CommunitySigningRoot()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(root, enrichment.SigningRoot()) {
		t.Fatal("optional channel anchor differs from core")
	}
}
