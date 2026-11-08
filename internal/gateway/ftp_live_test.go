package gateway

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/policy"
)

func TestFTPPyftpdlibPreventiveUploadsAndCommands(t *testing.T) {
	python := os.Getenv("NETCAP_FTP_PYTHON")
	if python == "" {
		t.Skip("set NETCAP_FTP_PYTHON to a Python environment with pyftpdlib==2.1.0")
	}
	root := t.TempDir()
	commands := filepath.Join(t.TempDir(), "commands")
	// An owned loopback server, pinned before import; no external targets.
	script := `import importlib.metadata, sys
assert importlib.metadata.version('pyftpdlib') == '2.1.0'
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
a = DummyAuthorizer()
a.add_user('tester', 'opaque-ftp-secret', sys.argv[1], perm='elradfmwMT')
class OwnedHandler(FTPHandler):
    def pre_process_command(self, line, cmd, arg):
        if cmd in ('STOR', 'DELE'):
            with open(sys.argv[2], 'a') as f:
                f.write(cmd + ' ' + arg + '\n')
        return super().pre_process_command(line, cmd, arg)
OwnedHandler.authorizer = a
s = FTPServer(('127.0.0.1', 0), OwnedHandler)
print(s.socket.getsockname()[1], flush=True)
s.serve_forever(timeout=0.1)
`
	p := exec.Command(python, "-u", "-c", script, root, commands)
	stdout, err := p.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Process.Kill(); p.Wait() })
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(stdout).ReadString('\n'); ready <- strings.TrimSpace(line) }()
	var port string
	select {
	case port = <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("FTP fixture not ready")
	}
	if port == "" {
		t.Fatal("pinned pyftpdlib fixture failed startup")
	}
	eval, err := policy.Compile(policy.Bundle{Version: "1", ID: "ftp-live", Mode: "enforce", Default: "allow", Rules: []policy.Rule{
		{ID: "block-write", Phase: "request", Action: "deny", Expression: `(Protocol == "ftp" && Method == "DELE") || Body contains "forbidden"`},
		{ID: "block-download", Phase: "response", Action: "deny", Expression: `Protocol == "ftp" && Body contains "forbidden"`},
	}})
	if err != nil {
		t.Fatal(err)
	}
	c, _, _ := startTCPGateway(t, Config{Protocol: "ftp", Upstream: net.JoinHostPort("127.0.0.1", port)}, eval)
	r := bufio.NewReader(c)
	want := func(code string) {
		t.Helper()
		b, e := r.ReadString('\n')
		if e != nil || !strings.HasPrefix(b, code+" ") {
			t.Fatalf("FTP response: %q %v want %s", b, e, code)
		}
	}
	want("220")
	for _, v := range []struct{ line, code string }{{"USER tester\r\n", "331"}, {"PASS opaque-ftp-secret\r\n", "230"}, {"TYPE I\r\n", "200"}, {"PORT 127,0,0,1,1,1\r\n", "502"}, {"EPRT |1|127.0.0.2|1234|\r\n", "502"}, {"AUTH TLS\r\n", "502"}, {"MODE Z\r\n", "502"}} {
		writeSplit(t, c, []byte(v.line))
		want(v.code)
	}
	upload := func(path, body, code string) {
		t.Helper()
		fmt.Fprint(c, "EPSV\r\n")
		reply, e := r.ReadString('\n')
		if e != nil {
			t.Fatal(e)
		}
		n, e := ftpPassivePort([]byte(reply))
		if e != nil {
			t.Fatalf("EPSV %q: %v", reply, e)
		}
		d, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: n})
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		writeSplit(t, c, []byte("STOR "+path+"\r\n"))
		want("150")
		writeSplit(t, d, []byte(body))
		d.CloseWrite()
		want(code)
	}
	upload("safe.txt", "safe-content", "226")
	upload("blocked.txt", "forbidden-at-end", "550")
	if b, e := os.ReadFile(filepath.Join(root, "safe.txt")); e != nil || string(b) != "safe-content" {
		t.Fatalf("safe upload %q %v", b, e)
	}
	if _, e := os.Stat(filepath.Join(root, "blocked.txt")); !os.IsNotExist(e) {
		t.Fatalf("denied upload created origin file: %v", e)
	}
	writeSplit(t, c, []byte("DELE safe.txt\r\n"))
	want("550")
	if _, e := os.Stat(filepath.Join(root, "safe.txt")); e != nil {
		t.Fatal("denied DELE had native effect")
	}
	if b, e := os.ReadFile(commands); e != nil || string(b) != "STOR safe.txt\n" {
		t.Fatalf("denied command reached FTP origin: %q %v", b, e)
	}
	// RETR uses the gateway-owned passive path and the same complete-message gate.
	fmt.Fprint(c, "EPSV\r\n")
	reply, _ := r.ReadString('\n')
	n, e := ftpPassivePort([]byte(reply))
	if e != nil {
		t.Fatal(e)
	}
	d, e := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", n))
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	d.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprint(c, "RETR safe.txt\r\n")
	want("150")
	b, e := io.ReadAll(d)
	if e != nil || string(b) != "safe-content" {
		t.Fatalf("RETR %q %v", b, e)
	}
	want("226")
	if e := os.WriteFile(filepath.Join(root, "download.txt"), []byte("forbidden-download"), 0600); e != nil {
		t.Fatal(e)
	}
	fmt.Fprint(c, "EPSV\r\n")
	reply, _ = r.ReadString('\n')
	n, e = ftpPassivePort([]byte(reply))
	if e != nil {
		t.Fatal(e)
	}
	blocked, e := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", n))
	if e != nil {
		t.Fatal(e)
	}
	defer blocked.Close()
	blocked.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprint(c, "RETR download.txt\r\n")
	want("150")
	if b, e := io.ReadAll(blocked); e != nil || len(b) != 0 {
		t.Fatalf("denied RETR leaked data: %q %v", b, e)
	}
	c.Close()
}

func TestFTPMultilineAndPassiveDestinationValidation(t *testing.T) {
	g := &Gateway{cfg: Config{IOTimeout: time.Second, MaxMessageBytes: 512}}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() { b.Write([]byte("220-first\r\n intermediate text\r\n220 ready\r\n")) }()
	reply, code, err := g.ftpReply(t.Context(), a, bufio.NewReader(a))
	if err != nil || code != 220 || !strings.Contains(string(reply), "intermediate") {
		t.Fatalf("multiline: %q %d %v", reply, code, err)
	}
	for _, r := range []string{"229 (|||21|)", "229 (|||65536|)", "229 (|1|127.0.0.2|2048|)", "229 (|||0|)"} {
		if _, e := ftpPassivePort([]byte(r)); e == nil {
			t.Fatalf("unsafe endpoint %q", r)
		}
	}
}
