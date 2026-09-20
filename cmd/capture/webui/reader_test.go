package webui

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/types"
)

func auditReaderFixture(t *testing.T, compressed bool, header *types.Header, records ...[]byte) *AuditRecordReader {
	t.Helper()
	var data bytes.Buffer
	w := delimited.NewWriter(&data)
	if header != nil {
		if err := w.PutProto(header); err != nil {
			t.Fatal(err)
		}
	}
	for _, record := range records {
		if err := w.Put(record); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "records.ncap")
	if compressed {
		var zipped bytes.Buffer
		gz := gzip.NewWriter(&zipped)
		if _, err := gz.Write(data.Bytes()); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		data = zipped
		path += ".gz"
	}
	if err := os.WriteFile(path, data.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := NewAuditRecordReader(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	return r
}

func TestAuditRecordReaderNextAs(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind types.Type
		want proto.Message
		next func(*AuditRecordReader) (proto.Message, error)
	}{
		{"connection", types.Type_NC_Connection, &types.Connection{SrcIP: "192.0.2.1", NumPackets: 42}, func(r *AuditRecordReader) (proto.Message, error) {
			return r.NextAs[*types.Connection]()
		}},
		{"service", types.Type_NC_Service, &types.Service{Name: "https", Port: 443}, func(r *AuditRecordReader) (proto.Message, error) {
			return r.NextAs[*types.Service]()
		}},
		{"device", types.Type_NC_DeviceProfile, &types.DeviceProfile{MacAddr: "00:11:22:33:44:55", NumPackets: 7}, func(r *AuditRecordReader) (proto.Message, error) {
			return r.NextAs[*types.DeviceProfile]()
		}},
	} {
		for _, compression := range []struct {
			name string
			gzip bool
		}{{"plain", false}, {"gzip", true}} {
			t.Run(tc.name+"/"+compression.name, func(t *testing.T) {
				payload, err := proto.Marshal(tc.want)
				if err != nil {
					t.Fatal(err)
				}
				r := auditReaderFixture(t, compression.gzip, &types.Header{Type: tc.kind}, payload, payload)
				if _, err := r.ReadHeader(); err != nil {
					t.Fatal(err)
				}
				got, err := tc.next(r)
				if err != nil || !proto.Equal(got, tc.want) {
					t.Fatalf("NextAs = (%v, %v), want %v", got, err, tc.want)
				}
				// The interface constraint must preserve the header-selected concrete type.
				got, err = r.NextAs[proto.Message]()
				if err != nil || !proto.Equal(got, tc.want) {
					t.Fatalf("NextAs[proto.Message] = (%v, %v), want %v", got, err, tc.want)
				}
				got, err = r.NextAs[proto.Message]()
				if got != nil || err != io.EOF {
					t.Fatalf("NextAs at EOF = (%v, %v), want (nil, EOF)", got, err)
				}
			})
		}
	}
}

func TestAuditRecordReaderNextAsErrors(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		for _, tc := range []struct {
			name    string
			kind    types.Type
			records [][]byte
			want    error
		}{
			{"header-only", types.Type_NC_Connection, nil, io.EOF},
			{"unknown-type", types.Type(-1), nil, io.EOF},
			{"mismatch", types.Type_NC_Service, [][]byte{{}}, ErrAuditRecordTypeMismatch},
			{"malformed-record", types.Type_NC_Service, [][]byte{{0x80}}, io.ErrUnexpectedEOF},
		} {
			t.Run(fmt.Sprintf("%s/gzip=%t", tc.name, compressed), func(t *testing.T) {
				r := auditReaderFixture(t, compressed, &types.Header{Type: tc.kind}, tc.records...)
				if _, err := r.ReadHeader(); err != nil {
					t.Fatal(err)
				}
				got, err := r.NextAs[*types.Connection]()
				if got != nil || !errors.Is(err, tc.want) {
					t.Fatalf("NextAs = (%v, %v), want (nil, %v)", got, err, tc.want)
				}
				if tc.want == ErrAuditRecordTypeMismatch {
					for _, name := range []string{"*types.Service", "*types.Connection"} {
						if !strings.Contains(err.Error(), name) {
							t.Errorf("mismatch %q does not describe %s", err, name)
						}
					}
				}
				got, err = r.NextAs[*types.Connection]()
				if got != nil || err != io.EOF {
					t.Fatalf("NextAs after error = (%v, %v), want (nil, EOF)", got, err)
				}
			})
		}
	}
}

func TestAuditRecordReaderHeaderErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		records [][]byte
		want    error
	}{
		{"empty", nil, io.EOF},
		{"malformed", [][]byte{{0x80}}, io.ErrUnexpectedEOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := auditReaderFixture(t, false, nil, tc.records...)
			header, err := r.ReadHeader()
			if header != nil || !errors.Is(err, tc.want) {
				t.Fatalf("ReadHeader = (%v, %v), want (nil, %v)", header, err, tc.want)
			}
		})
	}
}

func TestAuditRecordReaderNextRecordCompatibility(t *testing.T) {
	r := auditReaderFixture(t, false, &types.Header{Type: types.Type_NC_Connection}, []byte{}, []byte{0x80})
	if _, err := r.ReadHeader(); err != nil {
		t.Fatal(err)
	}
	got, err := r.NextRecord()
	if _, ok := got.(*types.Connection); !ok || err != nil {
		t.Fatalf("NextRecord = (%T, %v), want (*types.Connection, nil)", got, err)
	}
	got, err = r.NextRecord()
	if got != nil || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("malformed NextRecord = (%v, %v)", got, err)
	}
	got, err = r.NextRecord()
	if got != nil || err != io.EOF {
		t.Fatalf("NextRecord at EOF = (%v, %v)", got, err)
	}
	r.recordType = types.Type(-1)
	got, err = r.NextRecord()
	if _, ok := got.(*types.Connection); !ok || err != io.EOF {
		t.Fatalf("unknown-type NextRecord = (%T, %v), want (*types.Connection, EOF)", got, err)
	}
}
