package collector

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

// Locally generated TLS records carry one fragmented BACnet/SC heartbeat. Only the
// authenticated, negotiated session may produce its message ID.
func TestIndustrialSecureConnect(t *testing.T) {
	for _, subproto := range []string{"hub.bsc.bacnet.org", "dc.bsc.bacnet.org", "unrelated"} {
		t.Run(subproto, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				s, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer s.Close()
				_ = s.SetDeadline(time.Now().Add(5 * time.Second))
				_, err = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Protocol: " + subproto + "\r\n\r\n")
				if err == nil {
					err = rw.Flush()
				}
				if err != nil {
					t.Error(err)
					return
				}
				_, err = io.CopyN(io.Discard, rw, 22)
				if err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			raw, err := net.DialTimeout("tcp", server.Listener.Addr().String(), 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			rec := &dsbRecordingConn{Conn: raw}
			var keys bytes.Buffer
			cfg := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			cfg.ServerName = "127.0.0.1"
			cfg.KeyLogWriter = &keys
			c := tls.Client(rec, cfg)
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			_, err = io.WriteString(c, "GET /sc HTTP/1.1\r\nHost: fixture\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: "+subproto+"\r\n\r\n")
			if err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(c), nil)
			if err != nil || response.StatusCode != 101 {
				t.Fatalf("upgrade: %v", err)
			}
			for _, frame := range [][]byte{{2, 0x82, 1, 2, 3, 4, 0x0a ^ 1, 0 ^ 2}, {0x89, 0x80, 1, 2, 3, 4}, {0x80, 0x82, 1, 2, 3, 4, 0x12 ^ 1, 0x34 ^ 2}} {
				if _, err = c.Write(frame); err != nil {
					t.Fatal(err)
				}
			}
			_, _ = io.Copy(io.Discard, c)
			_ = c.Close()
			wrong := new(bytes.Buffer)
			for _, line := range strings.Split(keys.String(), "\n") {
				f := strings.Fields(line)
				if len(f) == 3 {
					wrong.WriteString(f[0] + " " + f[1] + " " + strings.Repeat("0", len(f[2])) + "\n")
				}
			}
			for _, k := range []struct {
				name string
				data []byte
			}{{"valid", keys.Bytes()}, {"absent", nil}, {"wrong", wrong.Bytes()}} {
				t.Run(k.name, func(t *testing.T) {
					path := tlsCaptureWithKeys(t, rec.chunks, k.data)
					out := runVoIP(t, path, "BACnetIP", 1)
					want := k.name == "valid" && subproto != "unrelated"
					if _, err := os.Stat(filepath.Join(out, "BACnetIP.ncap")); os.IsNotExist(err) && !want {
						return
					}
					rows := bookRecords(t, out, "BACnetIP", func() *types.BACnetIP { return new(types.BACnetIP) })
					if want {
						if len(rows) != 1 || rows[0].Carrier != "BACnet/SC" || rows[0].SCMessageID != 0x1234 || rows[0].BVLCFunctionName != "Heartbeat-Request" || rows[0].Assembly.GetStatus() != "complete" || rows[0].SrcPort != 12345 || rows[0].CommunityID == "" {
							t.Fatalf("wrong decoded heartbeat: %v", rows)
						}
					} else if len(rows) != 0 {
						t.Fatalf("unexpected BACnet/SC records: %v", rows)
					}
				})
			}
		})
	}
}
