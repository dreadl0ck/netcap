package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/secret"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

type formSecretWriter struct {
	netio.AuditRecordWriter
	records []*types.Secret
}

func (w *formSecretWriter) Write(m proto.Message) error {
	w.records = append(w.records, proto.Clone(m).(*types.Secret))
	return nil
}

func TestHTTPFormAliasesEmitAttributedSecrets(t *testing.T) {
	old, count := secret.Decoder.Writer, secret.Decoder.NumRecordsWritten
	defer func() { secret.Decoder.Writer, secret.Decoder.NumRecordsWritten = old, count }()
	for _, fields := range []string{"email=analyst&password=known", "userid=analyst&pswrd=known", "EMAIL=analyst&PASSWORD=known"} {
		w := &formSecretWriter{}
		secret.Decoder.Writer = w
		request := fmt.Sprintf("POST /login HTTP/1.1\r\nHost: fixture.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s", len(fields), fields)
		captureHTTP(t, core.DataFragments{wireFragment(0, []byte(request), 10), wireFragment(1, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 11)})
		if len(w.records) != 1 || w.records[0].User != "analyst" || w.records[0].Password != "known" || w.records[0].CommunityID != "1:fixture" || w.records[0].Timestamp != time.Unix(10, 123).UnixNano() {
			t.Fatal(fields, w.records)
		}
	}
}

func TestHTTPNonUTF8HeadersRemainPairable(t *testing.T) {
	request := []byte("GET /raw-\xff HTTP/1.1\r\nHost: host-\x80.test\r\n\r\n")
	records := captureHTTP(t, core.DataFragments{wireFragment(0, request, 10), wireFragment(1, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 11)})
	if len(records) != 1 || records[0].StatusCode != 200 || records[0].Method != "GET" || !bytes.Equal(records[0].RawRequestLine, request[:bytes.Index(request, []byte("\r\n"))+2]) {
		t.Fatal(records)
	}
	if !strings.Contains(records[0].Host, `\x80`) || !strings.Contains(records[0].URL, `\xff`) {
		t.Fatal(records[0])
	}
	data, err := json.Marshal(records[0])
	if err != nil || bytes.Contains(data, []byte("\ufffd")) {
		t.Fatal("HTTP evidence lost invalid octets", string(data), err)
	}
}
