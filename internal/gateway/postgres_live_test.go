package gateway

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

// The opt-in live fixture must be an isolated server with user tester/database
// test and trust authentication. Password/SCRAM relay uses instrumented fixtures.
func pgTrustLogin(t *testing.T, c net.Conn) {
	t.Helper()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(startupPacket()); err != nil {
		t.Fatal(err)
	}
	for {
		b, err := readPG(c, false)
		if err != nil {
			t.Fatal(err)
		}
		if b[0] == 'E' {
			t.Fatalf("startup rejected: %q", b)
		}
		if b[0] == 'Z' {
			return
		}
	}
}
func pgCollect(t *testing.T, c net.Conn) []byte {
	t.Helper()
	var result []byte
	for {
		b, err := readPG(c, false)
		if err != nil {
			t.Fatal(err)
		}
		if b[0] == 'E' {
			t.Fatalf("server error: %q", b)
		}
		result = append(result, b...)
		if b[0] == 'Z' {
			return result
		}
	}
}
func TestRealPostgresExtendedAndNoDeniedEffect(t *testing.T) {
	addr := os.Getenv("GATEWAY_POSTGRES_ADDR")
	if addr == "" {
		t.Skip("set GATEWAY_POSTGRES_ADDR to isolated PostgreSQL tester/test with trust authentication")
	}
	direct, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	pgTrustLogin(t, direct)
	table := fmt.Sprintf("gateway_test_%d", time.Now().UnixNano())
	direct.Write(pgFrame('Q', []byte("CREATE TABLE "+table+" (v integer)\x00")))
	pgCollect(t, direct)
	defer func() { direct.Write(pgFrame('Q', []byte("DROP TABLE "+table+"\x00"))); pgCollect(t, direct) }()
	c, _, _ := startTCPGateway(t, Config{Protocol: "postgres", Upstream: addr}, compileGatewayPolicy(t, `Protocol == "postgres" && Method == "EXECUTE" && Attributes["db.query"] startsWith "INSERT"`))
	pgTrustLogin(t, c)
	// A real backend requires gateway-injected Flush for Parse/Bind completion.
	c.Write(pgFrame('P', []byte("s\x00SELECT 42\x00\x00\x00")))
	pgReceive(t, c, '1')
	c.Write(pgFrame('B', []byte("p\x00s\x00\x00\x00\x00\x00\x00\x00")))
	pgReceive(t, c, '2')
	c.Write(bytes.Join([][]byte{pgFrame('E', []byte{'p', 0, 0, 0, 0, 0}), pgFrame('S', nil)}, nil))
	got := pgCollect(t, c)
	if !bytes.Contains(got, []byte("42")) {
		t.Fatalf("real extended SELECT returned no value: %x", got)
	}
	// A named suspended portal survives Sync while ReadyForQuery reports T.
	c.Write(pgFrame('Q', []byte("BEGIN\x00")))
	pgCollect(t, c)
	c.Write(pgFrame('P', []byte("series\x00SELECT generate_series(1,2)\x00\x00\x00")))
	pgReceive(t, c, '1')
	c.Write(pgFrame('B', []byte("cursor\x00series\x00\x00\x00\x00\x00\x00\x00")))
	pgReceive(t, c, '2')
	c.Write(bytes.Join([][]byte{pgFrame('E', []byte{'c', 'u', 'r', 's', 'o', 'r', 0, 0, 0, 0, 1}), pgFrame('S', nil)}, nil))
	got = pgCollect(t, c)
	if !bytes.Contains(got, pgFrame('s', nil)) {
		t.Fatalf("portal did not suspend: %x", got)
	}
	c.Write(bytes.Join([][]byte{pgFrame('E', []byte{'c', 'u', 'r', 's', 'o', 'r', 0, 0, 0, 0, 0}), pgFrame('S', nil)}, nil))
	got = pgCollect(t, c)
	if !bytes.Contains(got, []byte{'D', 0, 0, 0, 11, 0, 1, 0, 0, 0, 1, '2'}) {
		t.Fatalf("portal lost across transaction Sync: %x", got)
	}
	c.Write(pgFrame('Q', []byte("ROLLBACK\x00")))
	pgCollect(t, c)
	parse := pgFrame('P', []byte("s2\x00INSERT INTO "+table+" VALUES (1)\x00\x00\x00"))
	bind := pgFrame('B', []byte("p2\x00s2\x00\x00\x00\x00\x00\x00\x00"))
	execute := pgFrame('E', []byte{'p', '2', 0, 0, 0, 0, 0})
	c.Write(bytes.Join([][]byte{parse, bind, execute, pgFrame('S', nil)}, nil))
	pgReceive(t, c, '1')
	pgReceive(t, c, '2')
	pgReceive(t, c, 'E')
	c.Close()
	direct.Write(pgFrame('Q', []byte("SELECT count(*) FROM "+table+"\x00")))
	got = pgCollect(t, direct)
	// One text-format DataRow containing the single character zero.
	if !bytes.Contains(got, []byte{'D', 0, 0, 0, 11, 0, 1, 0, 0, 0, 1, '0'}) {
		t.Fatalf("denied Execute changed real table: %x", got)
	}
}
