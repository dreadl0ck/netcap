package investigate

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/protocoltest"
)

func TestExchangeCLIAndStrictSpecification(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("hello\n"))
	}()
	spec := protocoltest.Exchange{Version: 1, Network: "tcp", Address: listener.Addr().String(), Framing: protocoltest.Framing{Kind: "delimiter", Delimiter: []byte("\n"), MaxBytes: 64}, TimeoutMilliseconds: 2000, MaxTotalBytes: 128, Steps: []protocoltest.Step{{Receive: true, Expect: []byte("hello\n")}}}
	data, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "exchange.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	command := GetCommand()
	command.Writer = &output
	command.ErrWriter = &output
	if err := command.Run(context.Background(), []string{"investigate", "exchange", "--spec", path}); err != nil {
		t.Fatal(err)
	}
	var result protocoltest.Result
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "matched" || len(result.Observations) != 1 {
		t.Fatalf("CLI evidence: %+v", result)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("fixture did not terminate")
	}
	for _, invalid := range []string{`{"unexpected":true}`, string(data) + ` {}`} {
		if err := os.WriteFile(path, []byte(invalid), 0600); err != nil {
			t.Fatal(err)
		}
		if err := readExperimentSpec(path, &spec); err == nil {
			t.Fatal("ambiguous specification accepted")
		}
	}
}
