package stream

import (
	"errors"
	"testing"

	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/stream/tls"
	netio "github.com/dreadl0ck/netcap/io"
)

func TestTLSRecordWriterResetBeforeValidation(t *testing.T) {
	previous := tls.RecordDecoder.Writer
	t.Cleanup(func() { tls.RecordDecoder.Writer = previous })
	for _, tt := range []struct {
		name, include, exclude string
	}{
		{"include", "InvalidTLSSelection", ""},
		{"exclude", "TLSRecord", "InvalidTLSSelection"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			writer := netio.NewAuditRecordWriter(&netio.WriterConfig{Null: true})
			defer writer.Close(0)
			tls.RecordDecoder.Writer = writer
			selected, err := InitAbstractDecoders(&config.Config{IncludeDecoders: tt.include, ExcludeDecoders: tt.exclude})
			if selected != nil || !errors.Is(err, errInvalidAbstractDecoder) {
				t.Fatalf("selection = %v, error = %v", selected, err)
			}
			if tls.RecordDecoder.Writer != nil {
				t.Fatal("TLS record writer not reset before validation")
			}
		})
	}
}

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
