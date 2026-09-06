package tls

import (
	"sync"
	"testing"

	"github.com/dreadl0ck/netcap/types"
)

func TestCertificateConcurrentTimestampBounds(t *testing.T) {
	ResetCertificates()
	t.Cleanup(ResetCertificates)
	AddOrUpdateCertificate(&types.TLSCertificate{SHA256Fingerprint: "shared", Timestamp: 50})
	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			AddOrUpdateCertificate(&types.TLSCertificate{SHA256Fingerprint: "shared", Timestamp: int64(i)})
		}()
	}
	wg.Wait()
	// An interior timestamp must not replace either bound.
	AddOrUpdateCertificate(&types.TLSCertificate{SHA256Fingerprint: "shared", Timestamp: 25})
	entry := certificates.Items["shared"]
	if entry.FirstSeen != 0 || entry.LastSeen != 99 || entry.SeenCount != 102 {
		t.Fatalf("bounds/count = %d/%d/%d", entry.FirstSeen, entry.LastSeen, entry.SeenCount)
	}
}
