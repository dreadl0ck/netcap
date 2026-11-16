package dnsaudit

import (
	"bytes"
	"testing"

	"github.com/gopacket/gopacket/layers"
)

func TestResourceNamesHaveLosslessReadableCompanions(t *testing.T) {
	raw := []byte{'c', 0xff, '.', 't', 'e', 's', 't'}
	r := Record(&layers.DNS{Answers: []layers.DNSResourceRecord{{Type: layers.DNSTypeCNAME, CNAME: raw, NS: []byte("ns.test"), PTR: []byte("ptr.test")}}}, 1, false).Answers[0]
	if !bytes.Equal(r.CNAME, raw) || r.CNAMEText != `c\xff.test` || r.NSText != "ns.test" || r.PTRText != "ptr.test" {
		t.Fatalf("DNS name evidence lost: %+v", r)
	}
}
