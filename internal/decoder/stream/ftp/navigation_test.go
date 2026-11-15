package ftp

import (
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

type navigationWriter struct {
	netio.AuditRecordWriter
	records []*types.FTP
}

func (w *navigationWriter) Write(m proto.Message) error {
	w.records = append(w.records, proto.Clone(m).(*types.FTP))
	return nil
}

func TestFTPWithoutLogin(t *testing.T) {
	old, cfg, count := Decoder.Writer, config.Instance, Decoder.NumRecordsWritten
	t.Cleanup(func() { Decoder.Writer, config.Instance, Decoder.NumRecordsWritten = old, cfg, count })
	config.Instance = &config.Config{}
	for _, tc := range []struct {
		client, reply string
		count         int
	}{
		{"CWD x\r\nCDUP\r\nQUIT\r\n", "250 ok\r\n250 ok\r\n221 bye\r\n", 7},
		{"PWD\r\n", "257 current\r\n", 3},
		{"AUTH TLS\r\n", "234 proceed\r\n", 3},
	} {
		if !Decoder.CanDecode([]byte(tc.client), []byte("220 ready\r\n")) {
			t.Fatalf("missed %q", tc.client)
		}
		w := &navigationWriter{}
		Decoder.Writer = w
		c := &core.ConversationInfo{Data: core.DataFragments{&core.StreamData{Dir: reassembly.TCPDirServerToClient, RawData: []byte("220 ready\r\n")}, &core.StreamData{Dir: reassembly.TCPDirClientToServer, RawData: []byte(tc.client)}, &core.StreamData{Dir: reassembly.TCPDirServerToClient, RawData: []byte(tc.reply)}}}
		(&ftpReader{conversation: c}).Decode()
		if len(w.records) != tc.count {
			t.Fatalf("%q: got %d records; want %d", tc.client, len(w.records), tc.count)
		}
	}
	if Decoder.CanDecode([]byte("EHLO mail.test\r\nAUTH TLS\r\n"), []byte("220 smtp ready\r\n")) {
		t.Fatal("SMTP claimed as FTP")
	}
}
