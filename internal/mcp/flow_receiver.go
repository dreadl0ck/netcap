package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/dreadl0ck/netcap/internal/flowexport"
)

type receiverRequest struct {
	Operation       string            `json:"operation" jsonschema:"enum=start,enum=status,enum=stop,enum=query,enum=delete"`
	ReceiverID      string            `json:"receiver_id,omitempty"`
	Listen          string            `json:"listen,omitempty"`
	DurationSeconds int               `json:"duration_seconds,omitempty"`
	MaxOutputMB     int               `json:"max_output_mb,omitempty"`
	Query           *flowexport.Query `json:"query,omitempty"`
}

func (s *Server) registerFlowReceiver() error {
	return localOperation(s, "flow_receiver", "Owned UDP NetFlow/IPFIX/sFlow receiver lifecycle using the native decoder/recorder. start requires literal loopback listen (port 0 supported), duration_seconds 1..300 and max_output_mb 1..8. Returns receiver_id/address; status reports health, stop finalizes, query uses an explicit exporter/format/domain/time scope after completion, delete removes owned records. Shares the eight-job bound; byte budget is checked after each bounded datagram. Raw UDP exporter addresses are not authenticated identities.", true, func(ctx context.Context, r receiverRequest) (any, error) {
		if r.Operation != "start" && (r.Listen != "" || r.DurationSeconds != 0 || r.MaxOutputMB != 0) {
			return nil, fmt.Errorf("start parameters cannot be used by other operations")
		}
		if r.Operation != "query" && r.Query != nil {
			return nil, fmt.Errorf("query is only valid for query operation")
		}
		if r.Operation == "start" {
			return s.startFlowReceiver(ctx, r)
		}
		s.protocolJobs.mu.Lock()
		job := s.protocolJobs.entries[r.ReceiverID]
		if job == nil || job.directory == "" {
			s.protocolJobs.mu.Unlock()
			return nil, fmt.Errorf("unknown owned flow receiver")
		}
		switch r.Operation {
		case "stop":
			job.cancel()
			s.protocolJobs.mu.Unlock()
			return map[string]any{"receiver_id": r.ReceiverID, "stop_requested": true}, nil
		case "status":
			result := map[string]any{"receiver_id": r.ReceiverID, "address": job.address, "deadline": job.deadline, "completed": job.result != nil}
			if job.result != nil {
				result["result"] = job.result
			}
			s.protocolJobs.mu.Unlock()
			return result, nil
		case "delete":
			if job.result == nil || job.readers > 0 {
				s.protocolJobs.mu.Unlock()
				return nil, fmt.Errorf("stop, wait and finish active queries before deletion")
			}
			err := os.RemoveAll(job.directory)
			if err == nil {
				delete(s.protocolJobs.entries, r.ReceiverID)
			}
			s.protocolJobs.mu.Unlock()
			return map[string]any{"deleted": err == nil}, err
		case "query":
			if job.result == nil || r.Query == nil {
				s.protocolJobs.mu.Unlock()
				return nil, fmt.Errorf("completed receiver and explicit query required")
			}
			job.readers++
			s.protocolJobs.mu.Unlock()
			defer func() {
				s.protocolJobs.mu.Lock()
				job.readers--
				if job.readers == 0 && job.removeWhenDone {
					os.RemoveAll(job.directory)
				}
				s.protocolJobs.mu.Unlock()
			}()
			query := *r.Query
			if query.TimeBasis == "" {
				query.TimeBasis = "flow"
			}
			if query.GroupBy == "" {
				query.GroupBy = "srcIP"
			}
			if query.Limit == 0 {
				query.Limit = 100
			}
			bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			return flowexport.ReadReport(bounded, filepath.Join(job.directory, "FlowExports.jsonl"), query)
		default:
			s.protocolJobs.mu.Unlock()
			return nil, fmt.Errorf("unknown receiver operation")
		}
	})
}

func (s *Server) startFlowReceiver(parent context.Context, r receiverRequest) (any, error) {
	host, _, err := net.SplitHostPort(r.Listen)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		return nil, fmt.Errorf("literal loopback listen host:port required")
	}
	if r.DurationSeconds < 1 || r.DurationSeconds > 300 || r.MaxOutputMB < 1 || r.MaxOutputMB > 8 {
		return nil, fmt.Errorf("duration_seconds 1..300 and max_output_mb 1..8 required")
	}
	s.protocolJobs.mu.Lock()
	defer s.protocolJobs.mu.Unlock()
	if s.protocolJobs.entries == nil {
		s.protocolJobs.entries = map[string]*protocolJob{}
	}
	if len(s.protocolJobs.entries) >= 8 {
		return nil, fmt.Errorf("owned job capacity 8 reached")
	}
	address, err := net.ResolveUDPAddr("udp", r.Listen)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", address)
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(s.carve.dir, "flow-receiver-")
	if err != nil {
		conn.Close()
		return nil, err
	}
	recorder, err := flowexport.NewRecorder(dir, flowexport.DefaultConfig())
	if err != nil {
		conn.Close()
		os.RemoveAll(dir)
		return nil, err
	}
	if err := parent.Err(); err != nil {
		conn.Close()
		recorder.Close()
		os.RemoveAll(dir)
		return nil, err
	}
	id, err := randomHex(16)
	if err != nil {
		conn.Close()
		recorder.Close()
		os.RemoveAll(dir)
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(r.DurationSeconds)*time.Second)
	job := &protocolJob{address: conn.LocalAddr().String(), deadline: time.Now().Add(time.Duration(r.DurationSeconds) * time.Second), cancel: cancel, directory: dir}
	s.protocolJobs.entries[id] = job
	go func() {
		defer cancel()
		defer conn.Close()
		// A datagram is at most 65535 bytes; core parser state is independently bounded.
		buffer := make([]byte, 65535)
		var ordinal uint64
		var runErr error
		for ctx.Err() == nil {
			conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
			n, remote, err := conn.ReadFromUDP(buffer)
			if err != nil {
				var timeout net.Error
				if errors.As(err, &timeout) && timeout.Timeout() {
					continue
				}
				runErr = err
				break
			}
			err = recorder.Observe(buffer[:n], flowexport.Envelope{Exporter: remote.String(), Collector: conn.LocalAddr().String(), ReceivedNs: time.Now().UnixNano(), PacketOrdinal: ordinal})
			ordinal++
			if err == nil {
				err = recorder.Flush()
			}
			if err != nil {
				runErr = err
				break
			}
			info, err := os.Stat(filepath.Join(dir, "FlowExports.jsonl"))
			if err != nil {
				runErr = err
				break
			}
			if info.Size() > int64(r.MaxOutputMB)<<20 {
				runErr = fmt.Errorf("flow receiver byte budget reached after datagram; broader coverage is unknown")
				break
			}
		}
		if err := recorder.Close(); runErr == nil {
			runErr = err
		}
		healthRaw, err := os.ReadFile(filepath.Join(dir, "FlowExportsHealth.json"))
		if err != nil && runErr == nil {
			runErr = err
		}
		var health flowexport.RecorderHealth
		if json.Unmarshal(healthRaw, &health) != nil && runErr == nil {
			runErr = fmt.Errorf("invalid receiver health")
		}
		result := s.operationResult("flow-receiver", map[string]any{"receiver_id": id, "health": health, "limitations": []string{"UDP exporter addresses are transport metadata, not authenticated sensor identities", "finite observation window; no packet-capture or complete network-coverage claim"}}, runErr)
		s.protocolJobs.mu.Lock()
		job.result = result
		if job.removeWhenDone {
			os.RemoveAll(dir)
		}
		s.protocolJobs.mu.Unlock()
	}()
	return map[string]any{"receiver_id": id, "address": job.address, "deadline": job.deadline}, nil
}
