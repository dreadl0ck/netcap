package gateway

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"unicode/utf16"

	"github.com/dreadl0ck/netcap/internal/policy"
)

func smbUTF(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[2*i:], v)
	}
	return b
}
func smbPacket(cmd uint16, body []byte) []byte {
	b := make([]byte, 68+len(body))
	n := len(b) - 4
	b[1], b[2], b[3] = byte(n>>16), byte(n>>8), byte(n)
	copy(b[4:], "\xfeSMB")
	binary.LittleEndian.PutUint16(b[8:], 64)
	binary.LittleEndian.PutUint16(b[16:], cmd)
	binary.LittleEndian.PutUint64(b[28:], uint64(cmd)+1)
	binary.LittleEndian.PutUint32(b[40:], 1)
	binary.LittleEndian.PutUint64(b[44:], 7)
	copy(b[68:], body)
	return b
}
func smbSign(b []byte) {
	binary.LittleEndian.PutUint32(b[20:], binary.LittleEndian.Uint32(b[20:])|8)
	clear(b[52:68])
	h := hmac.New(sha256.New, []byte("owned-emulator-session-key"))
	h.Write(b[4:])
	copy(b[52:68], h.Sum(nil)[:16])
}
func smbCreate(path string) []byte {
	p := smbUTF(path)
	body := make([]byte, 56+len(p))
	binary.LittleEndian.PutUint16(body, 57)
	binary.LittleEndian.PutUint32(body[24:], 0x40000000)
	binary.LittleEndian.PutUint32(body[36:], 3)
	binary.LittleEndian.PutUint16(body[44:], 120)
	binary.LittleEndian.PutUint16(body[46:], uint16(len(p)))
	copy(body[56:], p)
	return smbPacket(5, body)
}

func smbTree(t *testing.T, c net.Conn) {
	t.Helper()
	p := smbUTF(`\\owned-server\share`)
	b := make([]byte, 8+len(p))
	binary.LittleEndian.PutUint16(b, 9)
	binary.LittleEndian.PutUint16(b[4:], 72)
	binary.LittleEndian.PutUint16(b[6:], uint16(len(p)))
	copy(b[8:], p)
	smbExchange(t, c, smbPacket(3, b))
}
func smbWrite(data string) []byte {
	b := make([]byte, 48+len(data))
	binary.LittleEndian.PutUint16(b, 49)
	binary.LittleEndian.PutUint16(b[2:], 112)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(data)))
	b[16] = 42
	copy(b[48:], data)
	return smbPacket(9, b)
}
func smbReadWire(c net.Conn) ([]byte, error) {
	var h [4]byte
	if _, e := io.ReadFull(c, h[:]); e != nil {
		return nil, e
	}
	n := int(h[1])<<16 | int(h[2])<<8 | int(h[3])
	if n > 1<<20 {
		return nil, errFrame
	}
	b := make([]byte, 4+n)
	copy(b, h[:])
	_, e := io.ReadFull(c, b[4:])
	return b, e
}

// The owned emulator implements real file effects independently of the gateway's
// parser. It qualifies this serial SMB2 profile, not Samba interoperability.
func smbDiskOrigin(t *testing.T, root string) *wireOrigin {
	return fixtureOrigin(t, func(c net.Conn, o *wireOrigin) {
		path := ""
		for {
			b, e := smbReadWire(c)
			if e != nil {
				return
			}
			o.record(b)
			if binary.LittleEndian.Uint32(b[20:])&8 != 0 {
				expected := append([]byte(nil), b...)
				smbSign(expected)
				if !hmac.Equal(expected[52:68], b[52:68]) {
					t.Error("origin rejected changed request signature")
					return
				}
			}
			cmd := binary.LittleEndian.Uint16(b[16:])
			reply := append([]byte(nil), b[:68]...)
			switch cmd {
			case 5:
				off, n := int(binary.LittleEndian.Uint16(b[112:])), int(binary.LittleEndian.Uint16(b[114:]))
				u := make([]uint16, n/2)
				for i := range u {
					u[i] = binary.LittleEndian.Uint16(b[4+off+2*i:])
				}
				path = string(utf16.Decode(u))
				if filepath.Base(path) != path {
					return
				}
				if e = os.WriteFile(filepath.Join(root, path), nil, 0600); e != nil {
					return
				}
				reply = append(reply, make([]byte, 88)...)
				binary.LittleEndian.PutUint16(reply[68:], 89)
				reply[132] = 42
			case 9:
				off, n := int(binary.LittleEndian.Uint16(b[70:])), int(binary.LittleEndian.Uint32(b[72:]))
				if e = os.WriteFile(filepath.Join(root, path), b[4+off:4+off+n], 0600); e != nil {
					return
				}
				reply = append(reply, make([]byte, 16)...)
				binary.LittleEndian.PutUint16(reply[68:], 17)
			case 8:
				data, e := os.ReadFile(filepath.Join(root, path))
				if e != nil {
					return
				}
				reply = append(reply, make([]byte, 16+len(data))...)
				binary.LittleEndian.PutUint16(reply[68:], 17)
				reply[70] = 80
				binary.LittleEndian.PutUint32(reply[72:], uint32(len(data)))
				copy(reply[84:], data)
			default:
				reply = append(reply, 4, 0, 0, 0)
			}
			n := len(reply) - 4
			reply[1], reply[2], reply[3] = byte(n>>16), byte(n>>8), byte(n)
			binary.LittleEndian.PutUint32(reply[20:], binary.LittleEndian.Uint32(reply[20:])|1)
			if binary.LittleEndian.Uint32(b[20:])&8 != 0 {
				smbSign(reply)
			}
			if _, e = c.Write(reply); e != nil {
				return
			}
		}
	})
}

func TestSMBReadMetadataAndResponseGate(t *testing.T) {
	for _, phase := range []string{"request", "response"} {
		t.Run(phase, func(t *testing.T) {
			root := t.TempDir()
			o := smbDiskOrigin(t, root)
			expression := `Protocol == "smb" && Method == "READ" && Attributes["smb.path"] == "read.txt" && Attributes["smb.share"] == "\\\\owned-server\\share"`
			if phase == "response" {
				expression += ` && Body contains "forbidden-read-data"`
			}
			p, err := policy.Compile(policy.Bundle{Version: "1", ID: "smb-read", Mode: "enforce", Default: "allow", Rules: []policy.Rule{{ID: "block-read", Phase: phase, Action: "deny", Expression: expression}}})
			if err != nil {
				t.Fatal(err)
			}
			c, _, _ := startTCPGateway(t, Config{Protocol: "smb", Upstream: o.listener.Addr().String()}, p)
			smbTree(t, c)
			smbExchange(t, c, smbCreate("read.txt"))
			smbExchange(t, c, smbWrite("forbidden-read-data"))
			body := make([]byte, 48)
			binary.LittleEndian.PutUint16(body, 49)
			binary.LittleEndian.PutUint32(body[4:], 100)
			body[16] = 42
			read := smbPacket(8, body)
			smbSign(read)
			writeSplit(t, c, read)
			b, e := io.ReadAll(c)
			if e != nil || len(b) != 0 {
				t.Fatalf("read denied bytes %x %v", b, e)
			}
			o.wait(t)
			seen := bytes.Contains(o.snapshot(), read)
			if seen != (phase == "response") {
				t.Fatalf("READ request forwarding=%v phase=%s", seen, phase)
			}
		})
	}
}

func FuzzSMBCompoundBounds(f *testing.F) {
	f.Add(smbCreate("seed.txt"))
	f.Add(smbWrite("seed"))
	f.Add([]byte{0, 0, 0, 64})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		smbParts(b, false, 128)
		smbParts(b, true, 128)
	})
}
func smbExchange(t *testing.T, c net.Conn, b []byte) []byte {
	t.Helper()
	writeSplit(t, c, b)
	reply, e := smbReadWire(c)
	if e != nil {
		t.Fatal(e)
	}
	return reply
}

func TestSMBPreventiveFileEffectsAndSignedRelay(t *testing.T) {
	root := t.TempDir()
	o := smbDiskOrigin(t, root)
	var events []policy.Event
	var mu sync.Mutex
	eval := evaluateFunc(func(e policy.Event) (policy.Decision, error) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, e)
		v := "allow"
		if e.Attributes["smb.path"] == "forbidden.txt" || strings.Contains(e.Body, "forbidden") {
			v = "deny"
		}
		return policy.Decision{Verdict: v}, nil
	})
	c, _, _ := startTCPGateway(t, Config{Protocol: "smb", Upstream: o.listener.Addr().String()}, eval)
	auth := make([]byte, 24+len("opaque-auth-secret"))
	binary.LittleEndian.PutUint16(auth, 25)
	binary.LittleEndian.PutUint16(auth[12:], 88)
	binary.LittleEndian.PutUint16(auth[14:], uint16(len("opaque-auth-secret")))
	copy(auth[24:], "opaque-auth-secret")
	smbExchange(t, c, smbPacket(1, auth))
	smbTree(t, c)
	create := smbCreate("allowed.txt")
	smbSign(create)
	response := smbExchange(t, c, create)
	expected := append([]byte(nil), response...)
	smbSign(expected)
	if !bytes.Equal(expected, response) {
		t.Fatal("response signing bytes changed")
	}
	allowed := smbWrite("safe-content")
	smbSign(allowed)
	smbExchange(t, c, allowed)
	blocked := smbWrite("forbidden-content")
	smbSign(blocked)
	writeSplit(t, c, blocked)
	if b, e := io.ReadAll(c); e != nil || len(b) != 0 {
		t.Fatalf("denial must close without forged reply: %x %v", b, e)
	}
	o.wait(t)
	b, e := os.ReadFile(filepath.Join(root, "allowed.txt"))
	if e != nil || string(b) != "safe-content" {
		t.Fatalf("wrong native effect: %q %v", b, e)
	}
	wire := o.snapshot()
	if !bytes.Contains(wire, create) || !bytes.Contains(wire, allowed) || bytes.Contains(wire, blocked) {
		t.Fatal("signed request mutated or denied bytes forwarded")
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Contains(fmt.Sprint(events), "opaque-auth-secret") {
		t.Fatal("authentication exposed to policy/log projection")
	}
	if events[len(events)-1].Attributes["smb.path"] != "allowed.txt" {
		t.Fatal("handle lost path metadata")
	}
}

func TestSMBForbiddenCreateAndCompoundHaveNoNativeEffect(t *testing.T) {
	for _, compound := range []bool{false, true} {
		t.Run(fmt.Sprint(compound), func(t *testing.T) {
			root := t.TempDir()
			o := smbDiskOrigin(t, root)
			c, _, _ := startTCPGateway(t, Config{Protocol: "smb", Upstream: o.listener.Addr().String()}, denyMethod("WRITE"))
			b := smbCreate("forbidden.txt")
			smbTree(t, c)
			if compound {
				n := (len(b) - 4 + 7) &^ 7
				b = append(b, make([]byte, n-(len(b)-4))...)
				binary.LittleEndian.PutUint32(b[24:], uint32(n))
				w := smbWrite("forbidden")
				binary.LittleEndian.PutUint32(w[20:], 4)
				for i := 84; i < 100; i++ {
					w[i] = 255
				}
				b = append(b, w[4:]...)
				n = len(b) - 4
				b[1], b[2], b[3] = byte(n>>16), byte(n>>8), byte(n)
			} else {
				// A path rule must prevent CREATE itself, not undo the created file.
				c.Close()
				o.listener.Close()
				o.wait(t)
				o = smbDiskOrigin(t, root)
				c, _, _ = startTCPGateway(t, Config{Protocol: "smb", Upstream: o.listener.Addr().String()}, compileGatewayPolicy(t, `Attributes["smb.path"] == "forbidden.txt"`))
				smbTree(t, c)
			}
			writeSplit(t, c, b)
			io.ReadAll(c)
			if _, e := os.Stat(filepath.Join(root, "forbidden.txt")); !os.IsNotExist(e) {
				t.Fatalf("forbidden CREATE side effect: %v", e)
			}
			if bytes.Contains(o.snapshot(), b) {
				t.Fatal("denied compound reached origin")
			}
			o.listener.Close()
			o.wait(t)
		})
	}
}

func TestSMBMalformedAndUnsupportedNeverDial(t *testing.T) {
	bad := [][]byte{}
	for _, sig := range []string{"\xffSMB", "\xfdSMB", "\xfcSMB"} {
		b := smbCreate("x")
		copy(b[4:], sig)
		bad = append(bad, b)
	}
	b := smbCreate("x")
	binary.LittleEndian.PutUint32(b[24:], 64)
	bad = append(bad, b)
	b = smbCreate("x")
	binary.LittleEndian.PutUint16(b[112:], 65535)
	bad = append(bad, b)
	b = smbWrite("x")
	binary.LittleEndian.PutUint16(b[70:], 64)
	bad = append(bad, b)
	for _, cmd := range []uint16{10, 11, 12, 15, 17, 18} {
		bad = append(bad, smbPacket(cmd, make([]byte, 64)))
	}
	for i, b := range bad {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			o := fixtureOrigin(t, func(c net.Conn, o *wireOrigin) { o.record([]byte("connected")) })
			c, _, _ := startTCPGateway(t, Config{Protocol: "smb", Upstream: o.listener.Addr().String()}, allowAll())
			c.Write(b)
			io.ReadAll(c)
			if len(o.snapshot()) != 0 {
				t.Fatal("unsupported reached origin")
			}
			o.listener.Close()
			o.wait(t)
		})
	}
}

func TestSMBAllowedCompoundRelayedUnchanged(t *testing.T) {
	body := []byte{4, 0, 0, 0}
	first, second := smbPacket(13, body), smbPacket(13, body)
	binary.LittleEndian.PutUint64(second[28:], 99)
	first = append(first, make([]byte, 4)...)
	binary.LittleEndian.PutUint32(first[24:], uint32(len(first)-4))
	wire := append(first, second[4:]...)
	n := len(wire) - 4
	wire[1], wire[2], wire[3] = byte(n>>16), byte(n>>8), byte(n)
	reply := append([]byte(nil), wire...)
	binary.LittleEndian.PutUint32(reply[20:], 1)
	binary.LittleEndian.PutUint32(reply[len(first)+16:], 1)
	o := fixtureOrigin(t, func(c net.Conn, o *wireOrigin) {
		b, err := smbReadWire(c)
		if err != nil {
			t.Error(err)
			return
		}
		o.record(b)
		if !bytes.Equal(b, wire) {
			t.Error("compound changed")
			return
		}
		writeSplit(t, c, reply)
	})
	c, _, _ := startTCPGateway(t, Config{Protocol: "smb", Upstream: o.listener.Addr().String()}, allowAll())
	if got := smbExchange(t, c, wire); !bytes.Equal(got, reply) {
		t.Fatal("compound response changed")
	}
	o.wait(t)
}
