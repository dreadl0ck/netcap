package webui

import (
	"bytes"
	"compress/gzip"
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
		name   string
		kind   types.Type
		record proto.Message
		read   func(string) (any, error)
		want   any
	}{
		{"Connection", types.Type_NC_Connection, &types.Connection{SrcIP: "192.0.2.1", NumPackets: 42}, func(dir string) (any, error) {
			return readConnections(dir)
		}, []ConnectionSummary{{SrcIP: "192.0.2.1", NumPackets: 42}}},
		{"Service", types.Type_NC_Service, &types.Service{Name: "https", Port: 443}, func(dir string) (any, error) {
			return readServices(dir)
		}, []ServiceSummary{{Name: "https", Port: 443}}},
		{"DeviceProfile", types.Type_NC_DeviceProfile, &types.DeviceProfile{MacAddr: "00:11:22:33:44:55", NumPackets: 7}, func(dir string) (any, error) {
			return readDeviceProfiles(dir)
		}, []DeviceProfileSummary{{MacAddr: "00:11:22:33:44:55", NumPackets: 7}}},
	} {
		for _, scenario := range []string{"missing", "wrong-type", "valid"} {
			t.Run(tc.name+"/"+scenario, func(t *testing.T) {
				dir := t.TempDir()
				if scenario != "missing" {
					kind, record := tc.kind, tc.record
					if scenario == "wrong-type" {
						kind, record = types.Type_NC_Service, &types.Service{Name: "wrong"}
						if tc.kind == types.Type_NC_Service {
							kind, record = types.Type_NC_Connection, &types.Connection{SrcIP: "192.0.2.2"}
						}
					}
					var data bytes.Buffer
					gz := gzip.NewWriter(&data)
					writer := delimited.NewWriter(gz)
					if err := writer.PutProto(&types.Header{Type: kind}); err != nil {
						t.Fatal(err)
					}
					for range 2 {
						if err := writer.PutProto(record); err != nil {
							t.Fatal(err)
						}
					}
					if err := gz.Close(); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(dir, tc.name+".ncap.gz"), data.Bytes(), 0600); err != nil {
						t.Fatal(err)
					}
				}
				got, err := tc.read(dir)
				if err != nil {
					t.Fatal(err)
				}
				value := reflect.ValueOf(got)
				if scenario == "valid" {
					want := reflect.ValueOf(tc.want)
					if !reflect.DeepEqual(got, reflect.AppendSlice(want, want).Interface()) {
						t.Fatalf("read = %#v, want two copies of %#v", got, tc.want)
					}
				} else if value.IsNil() || value.Len() != 0 {
					t.Fatalf("read = %#v, want empty nonnil slice", got)
				}
			})
		}
	}
}
