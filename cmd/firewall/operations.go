package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewallfleet"
	"github.com/dreadl0ck/netcap/internal/firewallstate"
	"github.com/dreadl0ck/netcap/internal/runtimeobs"
	"github.com/urfave/cli/v3"
)

func startOperations(address string, monitor *runtimeobs.Monitor) (func(), error) {
	if address == "" {
		return func() {}, nil
	}
	if !loopbackAddress(address) {
		return nil, errors.New("operations-listen requires a literal loopback address")
	}
	l, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", monitor.Handler())
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) { firewallstate.WriteJSON(w, 200, monitor.Status()) })
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() { _ = server.Serve(l) }()
	return func() { _ = server.Close() }, nil
}

func operationsCommand() *cli.Command {
	return &cli.Command{Name: "fleet-operations", Usage: "preview/prune retention, export audit, or acknowledge archived audit (operations v1)", Flags: []cli.Flag{
		&cli.StringFlag{Name: "url", Required: true}, &cli.StringFlag{Name: "token-env", Required: true},
		&cli.StringFlag{Name: "operation", Required: true, Usage: "retention_preview | prune | audit_export | audit_ack"},
		&cli.StringFlag{Name: "input", Required: true, Usage: "strict JSON request including tenant/app scope; no credentials"},
		&cli.StringFlag{Name: "ca"}, &cli.StringFlag{Name: "cert"}, &cli.StringFlag{Name: "key"},
	}, Action: runOperations}
}

func runOperations(ctx context.Context, c *cli.Command) error {
	op := c.String("operation")
	if op != "retention_preview" && op != "prune" && op != "audit_export" && op != "audit_ack" {
		return errors.New("unsupported operations v1 operation")
	}
	u, err := firewallstate.Endpoint(c.String("url"))
	if err != nil {
		return errors.New("verified HTTPS or literal loopback HTTP origin required")
	}
	token, err := envToken(c.String("token-env"))
	if err != nil {
		return err
	}
	raw, err := readBounded(c.String("input"), firewallfleet.MaxRequestBytes)
	if err != nil {
		return err
	}
	var input firewallfleet.Request
	if err = firewallstate.Decode(raw, &input); err != nil {
		return errors.New("invalid operations request JSON")
	}
	tc, err := clientTLS(c.String("ca"), c.String("cert"), c.String("key"))
	if err != nil {
		return err
	}
	transport := &http.Transport{TLSClientConfig: tc, ResponseHeaderTimeout: 5 * time.Second, MaxConnsPerHost: 1}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	u.Path = "/api/v1/fleet/" + op
	method := http.MethodPost
	if op == "audit_export" {
		method = http.MethodGet
		q := u.Query()
		q.Set("tenant", input.Scope.Tenant)
		q.Set("app", input.Scope.App)
		q.Set("after", strconv.FormatInt(input.After, 10))
		q.Set("limit", strconv.Itoa(input.Limit))
		u.RawQuery = q.Encode()
		raw = nil
	}
	r, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(raw))
	if err != nil {
		return errors.New("invalid operations request")
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	response, err := client.Do(r)
	if err != nil {
		return errors.New("operations endpoint unavailable")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, firewallfleet.MaxSnapshotBytes+1))
	if err != nil || len(data) > firewallfleet.MaxSnapshotBytes {
		return errors.New("operations response exceeds bound")
	}
	if response.StatusCode != 200 {
		return fmt.Errorf("operations request failed (HTTP %d)", response.StatusCode)
	}
	if op == "audit_export" {
		meta := map[string]string{"next": response.Header.Get("X-Audit-Next"), "more": response.Header.Get("X-Audit-More"), "truncated": response.Header.Get("X-Audit-Truncated")}
		if err = json.NewEncoder(c.Root().ErrWriter).Encode(meta); err != nil {
			return err
		}
	}
	_, err = c.Root().Writer.Write(data)
	return err
}
