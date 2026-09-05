package stream

import (
	"testing"

	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/stream/tls"
)

func TestTLSRecordWriterSelection(t *testing.T) {
	previous := config.Instance
	t.Cleanup(func() { config.Instance = previous; tls.Decoder.Writer = nil; tls.RecordDecoder.Writer = nil })
	for _, tt := range []struct {
		include, exclude    string
		certificate, record bool
	}{
		{"TLSRecord", "", false, true},
		{"TLSCertificate,TLSRecord", "", true, true},
		{"TLSCertificate,TLSRecord", "TLSCertificate", false, true},
		{"TLSCertificate,TLSRecord", "TLSRecord", true, false},
		{"TLSRecord", "TLSRecord", false, false},
	} {
		c := *config.DefaultConfig
		c.Out, c.IncludeDecoders, c.ExcludeDecoders, c.Null, c.Proto, c.Quiet = t.TempDir(), tt.include, tt.exclude, true, false, true
		config.Instance = &c
		streams, err := InitDecoders(&c)
		if err != nil {
			t.Fatal(err)
		}
		abstract, err := InitAbstractDecoders(&c)
		if err != nil {
			t.Fatal(err)
		}
		if (tls.Decoder.Writer != nil) != tt.certificate || (tls.RecordDecoder.Writer != nil) != tt.record {
			t.Fatalf("include %q exclude %q: certificate=%v record=%v", tt.include, tt.exclude, tls.Decoder.Writer != nil, tls.RecordDecoder.Writer != nil)
		}
		if DefaultStreamDecoders[443] != tls.Decoder || DefaultStreamDecoders[8443] != tls.Decoder {
			t.Fatal("TLS stream decoder displaced")
		}
		for _, d := range streams {
			d.GetWriter().Close(0)
		}
		for _, d := range abstract {
			d.GetWriter().Close(0)
		}
	}
}
