package tlsdecrypt

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type recordingConn struct {
	net.Conn
	mu   sync.Mutex
	wire [2]bytes.Buffer
}

func (c *recordingConn) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	c.mu.Lock()
	_, _ = c.wire[1].Write(b[:n])
	c.mu.Unlock()
	return n, e
}
func (c *recordingConn) Write(b []byte) (int, error) {
	n, e := c.Conn.Write(b)
	c.mu.Lock()
	_, _ = c.wire[0].Write(b[:n])
	c.mu.Unlock()
	return n, e
}

func TestDecryptCapturedTLS(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, "authenticated-fixture-response")
			}))
			server.TLS = &tls.Config{MinVersion: version, MaxVersion: version}
			server.StartTLS()
			defer server.Close()
			raw, err := net.Dial("tcp", server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			recorder := &recordingConn{Conn: raw}
			defer recorder.Close()
			var keylog bytes.Buffer
			config := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			config.MinVersion, config.MaxVersion, config.KeyLogWriter = version, version, &keylog
			config.ServerName = "127.0.0.1"
			client := tls.Client(recorder, config)
			_ = client.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := client.Write([]byte("GET /fixture HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n")); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadAll(client); err != nil {
				t.Fatal(err)
			}
			_ = client.Close()
			keys := NewSecrets()
			keys.Add(keylog.Bytes())
			var records [2][]Record
			for side := range 2 {
				data := recorder.wire[side].Bytes()
				for len(data) >= 5 {
					n := int(binary.BigEndian.Uint16(data[3:5]))
					if len(data) < n+5 {
						t.Fatal("short fixture record")
					}
					records[side] = append(records[side], Record{Type: data[0], Version: binary.BigEndian.Uint16(data[1:]), Body: bytes.Clone(data[5 : n+5])})
					data = data[n+5:]
				}
			}
			session := Handshake(records)
			if session == nil {
				t.Fatal("handshake unavailable")
			}
			plaintext := session.Decrypt(keys, records)
			var request, response []byte
			for _, p := range plaintext {
				if p.Client {
					request = append(request, p.Data...)
				} else {
					response = append(response, p.Data...)
				}
			}
			if !bytes.Contains(request, []byte("GET /fixture HTTP/1.1")) || !bytes.Contains(response, []byte("authenticated-fixture-response")) {
				t.Fatalf("TLS %x did not decrypt both directions (suite %x)", version, session.Suite)
			}
			if len(session.Decrypt(NewSecrets(), records)) != 0 {
				t.Fatal("decrypted without keys")
			}
			for side := range 2 {
				for i := range records[side] {
					if records[side][i].Type == 23 {
						records[side][i].Body[len(records[side][i].Body)-1] ^= 1
					}
				}
			}
			if len(session.Decrypt(keys, records)) != 0 {
				t.Fatal("unauthenticated ciphertext produced application data")
			}
		})
	}
}

func TestConflictingCapturedSecretsAreRejected(t *testing.T) {
	keys := NewSecrets()
	random := bytes.Repeat([]byte{1}, 32)
	line := func(b byte) []byte {
		return []byte("CLIENT_RANDOM " + hex.EncodeToString(random) + " " + hex.EncodeToString(bytes.Repeat([]byte{b}, 48)) + "\n")
	}
	keys.Add(line(2))
	keys.Add(line(3))
	keys.Add(line(2))
	if keys.lookup("CLIENT_RANDOM", random) != nil {
		t.Fatal("conflicting keys admitted")
	}
}
