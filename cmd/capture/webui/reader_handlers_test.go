package webui

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/types"
)

func TestAuditRecordHandlerReaders(t *testing.T) {
	for _, tc := range []struct {
		name    string
		kind    types.Type
		records []proto.Message
		read    func(string) (any, error)
		want    any
	}{
		{"Connection", types.Type_NC_Connection, []proto.Message{
			&types.Connection{SrcIP: "192.0.2.1", NumPackets: 42, TotalSize: 10},
			&types.Connection{TotalSize: 30},
			&types.Connection{TotalSize: 20},
		}, func(dir string) (any, error) {
			return readConnections(dir)
		}, []ConnectionSummary{{TotalSize: 30}, {TotalSize: 20}, {SrcIP: "192.0.2.1", NumPackets: 42, TotalSize: 10}}},
		{"Service", types.Type_NC_Service, []proto.Message{
			&types.Service{Name: "https", Port: 443, BytesServer: 10},
			&types.Service{BytesClient: 30},
			&types.Service{BytesServer: 15, BytesClient: 5},
		}, func(dir string) (any, error) {
			return readServices(dir)
		}, []ServiceSummary{{BytesClient: 30}, {BytesServer: 15, BytesClient: 5}, {Name: "https", Port: 443, BytesServer: 10}}},
		{"DeviceProfile", types.Type_NC_DeviceProfile, []proto.Message{
			&types.DeviceProfile{MacAddr: "00:11:22:33:44:55", NumPackets: 7, Bytes: 100},
			&types.DeviceProfile{NumPackets: 30},
			&types.DeviceProfile{NumPackets: 20},
		}, func(dir string) (any, error) {
			return readDeviceProfiles(dir)
		}, []DeviceProfileSummary{{NumPackets: 30}, {NumPackets: 20}, {MacAddr: "00:11:22:33:44:55", NumPackets: 7, Bytes: 100}}},
	} {
		for _, scenario := range []string{"missing", "wrong-type", "header-only", "malformed-header", "invalid-gzip", "malformed-record", "valid"} {
			t.Run(tc.name+"/"+scenario, func(t *testing.T) {
				dir := t.TempDir()
				if scenario != "missing" {
					kind, records := tc.kind, tc.records
					if scenario == "wrong-type" {
						kind, records = types.Type_NC_Service, []proto.Message{&types.Service{Name: "wrong"}, &types.Service{Name: "also wrong"}}
						if tc.kind == types.Type_NC_Service {
							kind, records = types.Type_NC_Connection, []proto.Message{&types.Connection{SrcIP: "192.0.2.2"}, &types.Connection{}}
						}
					}
					if scenario == "header-only" {
						records = nil
					}
					var data bytes.Buffer
					gz := gzip.NewWriter(&data)
					writer := delimited.NewWriter(gz)
					if scenario == "malformed-header" {
						if err := writer.Put([]byte{0x80}); err != nil {
							t.Fatal(err)
						}
					} else if err := writer.PutProto(&types.Header{Type: kind}); err != nil {
						t.Fatal(err)
					}
					if scenario == "malformed-record" {
						// Valid framing allows the next record to be read after protobuf decoding fails.
						if err := writer.Put([]byte{0x80}); err != nil {
							t.Fatal(err)
						}
					}
					for _, record := range records {
						if err := writer.PutProto(record); err != nil {
							t.Fatal(err)
						}
					}
					if err := gz.Close(); err != nil {
						t.Fatal(err)
					}
					if scenario == "invalid-gzip" {
						data.Reset()
						data.WriteString("not a gzip file")
					}
					if err := os.WriteFile(filepath.Join(dir, tc.name+".ncap.gz"), data.Bytes(), 0600); err != nil {
						t.Fatal(err)
					}
				}
				got, err := tc.read(dir)
				if scenario == "malformed-header" || scenario == "invalid-gzip" {
					wantErr := io.ErrUnexpectedEOF
					if scenario == "invalid-gzip" {
						wantErr = gzip.ErrHeader
					}
					if !errors.Is(err, wantErr) || !reflect.ValueOf(got).IsNil() {
						t.Fatalf("read = (%#v, %v), want (nil, %v)", got, err, wantErr)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				value := reflect.ValueOf(got)
				if scenario == "valid" || scenario == "malformed-record" {
					if !reflect.DeepEqual(got, tc.want) {
						t.Fatalf("read = %#v, want %#v", got, tc.want)
					}
				} else if value.IsNil() || value.Len() != 0 {
					t.Fatalf("read = %#v, want empty nonnil slice", got)
				}
			})
		}
	}
}
