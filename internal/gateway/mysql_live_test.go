package gateway

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

// This opt-in fixture uses synthetic credentials on an isolated 8.4 server.
// It exercises caching_sha2_password, including its RSA full-auth exchange.
func mysqlLiveScramble(password string, salt []byte) []byte {
	first := sha256.Sum256([]byte(password))
	second := sha256.Sum256(first[:])
	h := sha256.New()
	h.Write(second[:])
	h.Write(salt)
	mask := h.Sum(nil)
	b := make([]byte, 32)
	for i := range b {
		b[i] = first[i] ^ mask[i]
	}
	return b
}
func mysqlLiveLogin(t *testing.T, c net.Conn, deprecate bool) bool {
	t.Helper()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	seq, greeting, err := mysqlFixtureRead(c)
	if err != nil || seq != 0 {
		t.Fatalf("MySQL live greeting: %v", err)
	}
	lo, hi, _, caps, ok := mysqlGreeting(greeting)
	if !ok || len(greeting) < hi+25 {
		t.Fatal("live greeting invalid")
	}
	salt := append([]byte(nil), greeting[lo-9:lo-1]...)
	salt = append(salt, greeting[hi+13:hi+25]...)
	flags := mysqlProtocol41 | mysqlSecure | mysqlPlugin | 8
	if deprecate {
		flags |= mysqlDeprecateEOF
	}
	if flags&^caps != 0 {
		t.Fatal("required live capabilities absent")
	}
	password := "gateway-isolated-test"
	c.Write(mysqlPacket(1, mysqlFixtureLogin(flags, mysqlLiveScramble(password, salt))))
	expected := byte(2)
	needKey := false
	fullAuth := false
	for i := 0; i < 16; i++ {
		seq, b, err := mysqlFixtureRead(c)
		if err != nil || seq != expected || len(b) == 0 {
			t.Fatalf("live auth sequence: %d expected %d err %v", seq, expected, err)
		}
		expected++
		if b[0] == 0 {
			if !mysqlTerminal(b, true) {
				t.Fatal("live auth OK invalid")
			}
			return fullAuth
		}
		if b[0] == 0xff {
			t.Fatalf("live authentication rejected: %q", b)
		}
		if b[0] != 1 {
			t.Fatalf("unexpected caching_sha2 auth frame %x", b)
		}
		if len(b) == 2 && b[1] == 3 {
			continue
		}
		if len(b) == 2 && b[1] == 4 {
			fullAuth = true
			c.Write(mysqlPacket(expected, []byte{2}))
			expected++
			needKey = true
			continue
		}
		if !needKey {
			t.Fatal("unsolicited authentication key")
		}
		block, _ := pem.Decode(b[1:])
		if block == nil {
			t.Fatal("invalid auth public key")
		}
		public, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		key, ok := public.(*rsa.PublicKey)
		if !ok {
			t.Fatal("not RSA")
		}
		clear := append([]byte(password), 0)
		for j := range clear {
			clear[j] ^= salt[j%len(salt)]
		}
		encrypted, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, key, clear, nil)
		if err != nil {
			t.Fatal(err)
		}
		c.Write(mysqlPacket(expected, encrypted))
		expected++
		needKey = false
	}
	t.Fatal("authentication failed to converge")
	return false
}
func mysqlLiveQuery(t *testing.T, c net.Conn, query string, deprecate bool) []byte {
	t.Helper()
	c.Write(mysqlPacket(0, append([]byte{3}, []byte(query)...)))
	return mysqlTestResult(t, c, deprecate, false)
}

func TestRealMySQL84AuthenticationRelay(t *testing.T) {
	addr := os.Getenv("GATEWAY_MYSQL_ADDR")
	if addr == "" {
		t.Skip("set GATEWAY_MYSQL_ADDR to isolated MySQL 8.4")
	}
	c, _, _ := startTCPGateway(t, Config{Protocol: "mysql", Upstream: addr}, allowAll())
	full := mysqlLiveLogin(t, c, true)
	if os.Getenv("GATEWAY_MYSQL_REQUIRE_FULL_AUTH") == "1" && !full {
		t.Fatal("expected cold caching_sha2_password full auth; flush server privileges before this test")
	}
	t.Logf("caching_sha2_password full RSA authentication relayed: %v", full)
	mysqlLiveQuery(t, c, "SELECT 7", true)
	c.Write(mysqlPacket(0, []byte{1}))
	c.Close()
}

func TestRealMySQL84QueryAndPreparedPrevention(t *testing.T) {
	addr := os.Getenv("GATEWAY_MYSQL_ADDR")
	if addr == "" {
		t.Skip("set GATEWAY_MYSQL_ADDR to isolated MySQL 8.4 tester/test, password gateway-isolated-test")
	}
	for _, deprecate := range []bool{false, true} {
		t.Run(fmt.Sprint(deprecate), func(t *testing.T) {
			direct, err := net.DialTimeout("tcp", addr, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer direct.Close()
			mysqlLiveLogin(t, direct, deprecate)
			table := fmt.Sprintf("gateway_test_%d", time.Now().UnixNano())
			mysqlLiveQuery(t, direct, "CREATE TABLE "+table+" (v int)", deprecate)
			defer func() { mysqlLiveQuery(t, direct, "DROP TABLE "+table, deprecate) }()
			deniedQuery := "INSERT INTO " + table + " VALUES (99)"
			preparedQuery := "INSERT INTO " + table + " VALUES (?)"
			expression := fmt.Sprintf(`Protocol == "mysql" && ((Method == "QUERY" && Attributes["db.query"] == %q) || (Method == "STMT_EXECUTE" && Attributes["db.query"] == %q))`, deniedQuery, preparedQuery)
			p := compileGatewayPolicy(t, expression)
			c, _, _ := startTCPGateway(t, Config{Protocol: "mysql", Upstream: addr}, p)
			mysqlLiveLogin(t, c, deprecate)
			mysqlLiveQuery(t, c, "INSERT INTO "+table+" VALUES (7)", deprecate)
			c.Write(mysqlPacket(0, append([]byte{3}, []byte(deniedQuery)...)))
			_, b, err := mysqlFixtureRead(c)
			if err != nil || len(b) == 0 || b[0] != 0xff {
				t.Fatal("missing real query denial")
			}
			c.Close()
			c2, _, _ := startTCPGateway(t, Config{Protocol: "mysql", Upstream: addr}, p)
			mysqlLiveLogin(t, c2, deprecate)
			id, params := mysqlPrepareTest(t, c2, "SELECT ?", deprecate)
			if params != 1 {
				t.Fatal("real prepare lost parameters")
			}
			c2.Write(mysqlPacket(0, mysqlExecute(id, true)))
			mysqlTestResult(t, c2, deprecate, true)
			id, params = mysqlPrepareTest(t, c2, preparedQuery, deprecate)
			if params != 1 {
				t.Fatal("real INSERT parameter count")
			}
			c2.Write(mysqlPacket(0, mysqlExecute(id, true)))
			_, b, err = mysqlFixtureRead(c2)
			if err != nil || len(b) == 0 || b[0] != 0xff {
				t.Fatal("missing real prepared Execute denial")
			}
			c2.Close()
			wire := mysqlLiveQuery(t, direct, "SELECT count(*) FROM "+table, deprecate)
			rowSeq := byte(4)
			if deprecate {
				rowSeq = 3
			}
			if !bytes.Contains(wire, mysqlPacket(rowSeq, []byte{1, '1'})) {
				t.Fatalf("denied commands changed real table: %x", wire)
			}
		})
	}
}
