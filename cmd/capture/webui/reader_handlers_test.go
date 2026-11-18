package webui

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/types"
)

func TestAuditFieldValuesRejectsDamagedInput(t *testing.T) {
	body, err := proto.Marshal(&types.UDP{SrcPort: 5353})
	if err != nil {
		t.Fatal(err)
	}
	valid := auditReaderFixture(t, false, &types.Header{Type: types.Type_NC_UDP}, body)
	damaged := auditReaderFixture(t, true, &types.Header{Type: types.Type_NC_UDP}, body, []byte{0x80})
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, tc := range []struct {
		name, path, kind string
		ctx              context.Context
		status           int
	}{
		{"valid", valid.file.Name(), "UDP", t.Context(), http.StatusOK},
		{"wrong type", valid.file.Name(), "HTTP", t.Context(), http.StatusInternalServerError},
		{"damaged record", damaged.file.Name(), "UDP", t.Context(), http.StatusInternalServerError},
		{"canceled", valid.file.Name(), "UDP", canceled, http.StatusRequestTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			HandleAuditFieldValues(w, httptest.NewRequestWithContext(tc.ctx, http.MethodGet, "/api/audit/UDP/values", nil), tc.path, tc.kind)
			if w.Code != tc.status || bytes.Contains(w.Body.Bytes(), []byte(`"5353"`)) != (tc.status == http.StatusOK) {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestAuditFieldValuesAdmissionAndConfinement(t *testing.T) {
	reader := auditReaderFixture(t, false, &types.Header{Type: types.Type_NC_UDP})
	request := func(path string, want int) {
		t.Helper()
		w := httptest.NewRecorder()
		HandleAuditFieldValues(w, httptest.NewRequest(http.MethodGet, "/api/audit/UDP/values", nil), path, "UDP")
		if w.Code != want {
			t.Fatalf("status=%d want=%d: %s", w.Code, want, w.Body.String())
		}
	}
	func() {
		for range 2 {
			auditFieldSampleSlots <- struct{}{}
			defer func() { <-auditFieldSampleSlots }()
		}
		request(reader.file.Name(), http.StatusTooManyRequests)
	}()
	linked := filepath.Join(t.TempDir(), "linked.ncap")
	if err := os.Symlink(reader.file.Name(), linked); err == nil {
		request(linked, http.StatusForbidden)
	} else {
		t.Logf("symlink unavailable: %v", err)
	}
	request(reader.file.Name(), http.StatusOK)
}

func TestAuditFieldSampleCancellationStopsDecodedFrameRead(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var wire bytes.Buffer
	if err := delimited.NewWriter(&wire).PutProto(&types.HTTP{RequestBody: make([]byte, 256<<10)}); err != nil {
		t.Fatal(err)
	}
	input := &cancelingAuditInput{Reader: bytes.NewReader(wire.Bytes()), cancel: cancel}
	r := delimited.NewReader(auditContextReader{ctx: ctx, input: input})
	if data, err := r.NextWithLimit(1 << 20); data != nil || !errors.Is(err, context.Canceled) || input.read >= wire.Len() {
		t.Fatalf("sample read %d/%d bytes, returned %d bytes, error: %v", input.read, wire.Len(), len(data), err)
	}
}

func TestAuditFieldValuesBoundsCumulativeSampleBytes(t *testing.T) {
	body, err := proto.Marshal(&types.HTTP{Method: "GET", RequestBody: make([]byte, 9<<20)})
	if err != nil {
		t.Fatal(err)
	}
	for _, count := range []int{1, 2} {
		rows := [][]byte{body, body}
		reader := auditReaderFixture(t, true, &types.Header{Type: types.Type_NC_HTTP}, rows[:count]...)
		w := httptest.NewRecorder()
		HandleAuditFieldValues(w, httptest.NewRequest(http.MethodGet, "/api/audit/HTTP/values", nil), reader.file.Name(), "HTTP")
		want := http.StatusOK
		if count == 2 {
			want = http.StatusRequestEntityTooLarge
		}
		if w.Code != want || bytes.Contains(w.Body.Bytes(), []byte(`"GET"`)) != (count == 1) {
			t.Fatalf("records=%d status=%d body=%s", count, w.Code, w.Body.String())
		}
	}
}

func TestAuditRecordHandlerReaders(t *testing.T) {
	for _, tc := range []struct {
		name    string
		kind    types.Type
		records []proto.Message
		read    func(string) (any, error)
		want    any
	}{
		{"Connection", types.Type_NC_Connection, []proto.Message{
			&types.Connection{SrcIP: "192.0.2.1", NumPackets: 42, TotalSize: 10, TimestampFirst: 1700000000000000001, TimestampLast: 1700000000000000003},
			&types.Connection{TotalSize: 30},
			&types.Connection{TotalSize: 20},
		}, func(dir string) (any, error) {
			return readConnections(dir)
		}, []ConnectionSummary{
			{TotalSize: 30, TimestampFirstNs: "0", TimestampLastNs: "0"},
			{TotalSize: 20, TimestampFirstNs: "0", TimestampLastNs: "0"},
			{SrcIP: "192.0.2.1", NumPackets: 42, TotalSize: 10, TimestampFirst: 1700000000000000001, TimestampLast: 1700000000000000003, TimestampFirstNs: "1700000000000000001", TimestampLastNs: "1700000000000000003"},
		}},
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
