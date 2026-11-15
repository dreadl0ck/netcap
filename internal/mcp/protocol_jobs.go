package mcp

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/internal/protocoltest"
	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type protocolJob struct {
	address        string
	deadline       time.Time
	cancel         context.CancelFunc
	result         *mcplib.CallToolResult
	directory      string
	removeWhenDone bool
	readers        int
}
type protocolJobs struct {
	mu      sync.Mutex
	entries map[string]*protocolJob
}
type protocolListenerRequest struct {
	Mode     string                 `json:"mode" jsonschema:"enum=server,enum=proxy"`
	Listen   string                 `json:"listen"`
	Exchange *protocoltest.Exchange `json:"exchange,omitempty"`
	Proxy    *protocoltest.Proxy    `json:"proxy,omitempty"`
}

func (s *Server) registerProtocolJobs() error {
	if err := localOperation(s, "start_protocol_listener", "Start one bounded loopback TCP/TLS/peer-pinned UDP emulation or TCP/TLS application/passthrough proxy. Requires mode server + exchange OR mode proxy + proxy, and literal loopback listen address (port 0 supported). Returns job_id and actual address before waiting for a peer. Poll get_protocol_job; stop_protocol_job cancels. Maximum 8 retained jobs, 5 minutes each; byte fields are base64.", true, func(ctx context.Context, r protocolListenerRequest) (any, error) {
		host, _, err := net.SplitHostPort(r.Listen)
		if err != nil || !net.ParseIP(host).IsLoopback() {
			return nil, fmt.Errorf("literal loopback listen host:port required")
		}
		network := "tcp"
		timeout := 0
		if r.Mode == "server" && r.Exchange != nil && r.Proxy == nil {
			if err := r.Exchange.Validate(); err != nil {
				return nil, err
			}
			network = r.Exchange.Network
			timeout = r.Exchange.TimeoutMilliseconds
		} else if r.Mode == "proxy" && r.Proxy != nil && r.Exchange == nil {
			timeout = r.Proxy.TimeoutMilliseconds
			if r.Proxy.MaxTotalBytes < 1 || r.Proxy.MaxTotalBytes > 16<<20 || r.Proxy.MaxFrames < 1 || r.Proxy.MaxFrames > 10000 {
				return nil, fmt.Errorf("invalid proxy budgets")
			}
		} else {
			return nil, fmt.Errorf("select exactly one server exchange or proxy specification")
		}
		if timeout < 1 || timeout > 300000 {
			return nil, fmt.Errorf("timeoutMilliseconds must be 1..300000")
		}
		s.protocolJobs.mu.Lock()
		defer s.protocolJobs.mu.Unlock()
		if s.protocolJobs.entries == nil {
			s.protocolJobs.entries = map[string]*protocolJob{}
		}
		for id, job := range s.protocolJobs.entries {
			if job.result != nil && time.Since(job.deadline) > time.Hour {
				if job.directory != "" && job.readers == 0 {
					os.RemoveAll(job.directory)
				}
				delete(s.protocolJobs.entries, id)
			}
		}
		if len(s.protocolJobs.entries) >= 8 {
			return nil, fmt.Errorf("protocol job capacity 8 reached; collect completed jobs first")
		}
		jobCtx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Millisecond)
		var address string
		var run func() (any, error)
		var closeListener func() error
		if network == "udp" {
			listener, err := net.ListenPacket("udp", r.Listen)
			if err != nil {
				cancel()
				return nil, err
			}
			address = listener.LocalAddr().String()
			closeListener = listener.Close
			run = func() (any, error) { return protocoltest.ServeUDP(jobCtx, listener, *r.Exchange) }
		} else {
			listener, err := net.Listen("tcp", r.Listen)
			if err != nil {
				cancel()
				return nil, err
			}
			address = listener.Addr().String()
			closeListener = listener.Close
			run = func() (any, error) {
				if r.Mode == "proxy" {
					observations, err := protocoltest.ProxyOne(jobCtx, listener, *r.Proxy)
					mode, unit := r.Proxy.Mode, "application frames"
					if mode == "" {
						mode = "application"
					}
					if mode == "passthrough" {
						unit = "transport read chunks, not message boundaries; TLS remains end-to-end"
					}
					return map[string]any{"mode": mode, "evidenceUnit": unit, "observations": observations}, err
				}
				return protocoltest.ServeOne(jobCtx, listener, *r.Exchange)
			}
		}
		if err := ctx.Err(); err != nil {
			cancel()
			closeListener()
			return nil, err
		}
		id, err := randomHex(16)
		if err != nil {
			cancel()
			closeListener()
			return nil, err
		}
		job := &protocolJob{address: address, deadline: time.Now().Add(time.Duration(timeout) * time.Millisecond), cancel: cancel}
		s.protocolJobs.entries[id] = job
		go func() {
			defer cancel()
			defer closeListener()
			value, err := run()
			result := s.operationResult("protocol-job", value, err)
			s.protocolJobs.mu.Lock()
			job.result = result
			s.protocolJobs.mu.Unlock()
		}()
		return map[string]any{"job_id": id, "address": address, "deadline": job.deadline, "next_step": "Connect a peer, then get_protocol_job; stop_protocol_job cancels the owned listener."}, nil
	}); err != nil {
		return err
	}
	for _, stop := range []bool{false, true} {
		name, description := "get_protocol_job", "Poll one owned protocol job; running returns actual address/deadline, completion returns the full report or bounded artifact reference and errors. consume=true removes a completed job after returning its immutable result."
		if stop {
			name, description = "stop_protocol_job", "Cancel one owned protocol listener/proxy by job_id; poll get_protocol_job for final partial evidence."
		}
		stop := stop
		opts := []mcplib.ToolOption{mcplib.WithDescription(description), mcplib.WithString("job_id", mcplib.Required()), mcplib.WithReadOnlyHintAnnotation(false)}
		if !stop {
			opts = append(opts, mcplib.WithBoolean("consume"))
		}
		if err := s.addTool(server.ServerTool{Tool: mcplib.NewTool(name, opts...), Handler: func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
			id := req.GetString("job_id", "")
			s.protocolJobs.mu.Lock()
			defer s.protocolJobs.mu.Unlock()
			job := s.protocolJobs.entries[id]
			if job == nil {
				return errResult(fmt.Errorf("unknown or expired protocol job")), nil
			}
			if stop {
				job.cancel()
				return jsonResult(map[string]any{"job_id": id, "stop_requested": true}), nil
			}
			if job.result != nil {
				if req.GetBool("consume", false) {
					if job.readers > 0 {
						return errResult(fmt.Errorf("owned records have an active query")), nil
					}
					if job.directory != "" {
						os.RemoveAll(job.directory)
					}
					delete(s.protocolJobs.entries, id)
				}
				return job.result, nil
			}
			return jsonResult(map[string]any{"job_id": id, "address": job.address, "deadline": job.deadline, "completed": false}), nil
		}}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) stopProtocolJobs() {
	s.protocolJobs.mu.Lock()
	defer s.protocolJobs.mu.Unlock()
	for _, job := range s.protocolJobs.entries {
		job.cancel()
		job.removeWhenDone = true
		if job.result != nil && job.directory != "" && job.readers == 0 {
			os.RemoveAll(job.directory)
		}
	}
}
