package protocoltest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// ServeOne emulates one ordered TCP session. Receive and send steps are separate
// when a response depends on a request. A new invocation resets all variables.
func ServeOne(ctx context.Context, listener net.Listener, spec Exchange) (result Result, runErr error) {
	result = Result{Version: 1, Status: "error", Address: listener.Addr().String(), Observations: []Observation{}, Limitations: []string{"one ordered TCP session; UDP server emulation and TLS server exchange are unsupported"}}
	defer func() {
		if runErr != nil {
			result.Error = runErr.Error()
		}
	}()
	if err := spec.Validate(); err != nil {
		return result, err
	}
	if spec.Network != "tcp" || spec.TLS {
		return result, fmt.Errorf("server emulation supports plaintext TCP only")
	}
	data, _ := json.Marshal(spec)
	sum := sha256.Sum256(data)
	result.ConfigurationSHA256 = hex.EncodeToString(sum[:])
	ctx, cancel := context.WithTimeout(ctx, time.Duration(spec.TimeoutMilliseconds)*time.Millisecond)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	conn, err := listener.Accept()
	if err != nil {
		return result, err
	}
	defer conn.Close()
	return runConnection(ctx, conn, spec, result)
}
