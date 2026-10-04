/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package distributed

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

// ServerConfig configures a collector Server.
type ServerConfig struct {
	Identity  tls.Certificate
	Allowlist Allowlist
	Sink      *Sink

	MaxFrame         int           // default DefaultMaxFrame
	MaxConns         int           // default 256
	HandshakeTimeout time.Duration // default 10s
	IdleTimeout      time.Duration // max wait for the next frame, default 5m
	WriteTimeout     time.Duration // default 30s

	Logger *log.Logger // default log.Default()
}

// Server accepts agent connections and writes their batches into a Sink.
type Server struct {
	cfg ServerConfig
	tls *tls.Config
	sem chan struct{}

	mu       sync.Mutex
	ln       net.Listener
	conns    map[net.Conn]struct{}
	closing  bool
	sessions map[string]map[uint64]*session // client name → agent session

	wg sync.WaitGroup
}

// session tracks the highest written sequence number of one agent process,
// so batches resent after a lost ack are acknowledged without being written twice.
type session struct {
	mu      sync.Mutex
	lastSeq uint64
	used    time.Time
}

const maxSessionsPerClient = 16

// NewServer validates cfg and returns a Server.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Sink == nil {
		return nil, errors.New("server needs a sink")
	}
	if len(cfg.Allowlist) == 0 {
		return nil, errors.New("server needs a non-empty allowlist")
	}
	if len(cfg.Identity.Certificate) == 0 {
		return nil, errors.New("server needs an identity")
	}
	if cfg.MaxFrame <= 0 {
		cfg.MaxFrame = DefaultMaxFrame
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = 256
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = 10 * time.Second
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 5 * time.Minute
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = 30 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}

	return &Server{
		cfg:      cfg,
		tls:      ServerTLSConfig(cfg.Identity, cfg.Allowlist),
		sem:      make(chan struct{}, cfg.MaxConns),
		conns:    map[net.Conn]struct{}{},
		sessions: map[string]map[uint64]*session{},
	}, nil
}

// ErrServerClosed is returned by Serve after Shutdown.
var ErrServerClosed = errors.New("server closed")

// Serve accepts TCP connections on ln until Shutdown. It never panics on
// peer input: every per-connection failure is logged and ends that connection.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()

		return ErrServerClosed
	}
	s.ln = ln
	s.mu.Unlock()

	var backoff time.Duration

	for {
		c, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closing := s.closing
			s.mu.Unlock()
			if closing {
				return ErrServerClosed
			}

			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
				time.Sleep(backoff)

				continue
			}

			return err
		}
		backoff = 0

		select {
		case s.sem <- struct{}{}:
		default:
			s.cfg.Logger.Printf("collect: rejecting %s: %d connections open", c.RemoteAddr(), s.cfg.MaxConns)
			_ = c.Close()

			continue
		}

		if !s.track(c, true) {
			<-s.sem
			_ = c.Close()

			return ErrServerClosed
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			defer s.track(c, false)
			defer c.Close()

			s.handle(c)
		}()
	}
}

func (s *Server) track(c net.Conn, add bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if add {
		if s.closing {
			return false
		}
		s.conns[c] = struct{}{}
	} else {
		delete(s.conns, c)
	}

	return true
}

// Shutdown stops accepting, interrupts open connections, waits for their
// handlers to return, then closes the sink. Batches that were not acknowledged
// are resent by their agents.
func (s *Server) Shutdown(ctx context.Context) ([]SinkFileInfo, error) {
	s.mu.Lock()
	s.closing = true
	if s.ln != nil {
		_ = s.ln.Close()
	}
	// Unblock reads; a handler mid-write finishes that batch first.
	for c := range s.conns {
		_ = c.SetReadDeadline(time.Now())
	}
	s.mu.Unlock()

	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()

	var waitErr error
	select {
	case <-done:
	case <-ctx.Done():
		waitErr = fmt.Errorf("waiting for connections: %w", ctx.Err())
		s.mu.Lock()
		for c := range s.conns {
			_ = c.Close()
		}
		s.mu.Unlock()
		<-done
	}

	infos, err := s.cfg.Sink.Close()

	return infos, errors.Join(waitErr, err)
}

func (s *Server) handle(raw net.Conn) {
	var (
		logf = s.cfg.Logger.Printf
		addr = raw.RemoteAddr().String()
		conn = tls.Server(raw, s.tls)
	)

	if !s.arm(conn, s.cfg.HandshakeTimeout) {
		return
	}
	if err := conn.Handshake(); err != nil {
		logf("collect: %s: handshake failed: %v", addr, err)

		return
	}
	_ = conn.SetDeadline(time.Time{})

	client, err := PeerName(conn.ConnectionState(), s.cfg.Allowlist)
	if err != nil {
		logf("collect: %s: %v", addr, err)

		return
	}
	who := client + "@" + addr

	hello, err := s.readHello(conn)
	if err != nil {
		logf("collect: %s: hello: %v", who, err)
		s.sendError(conn, err.Error())

		return
	}
	if err = s.send(conn, FrameAck, EncodeAck(0)); err != nil {
		logf("collect: %s: hello ack: %v", who, err)

		return
	}

	sess := s.session(client, hello.Session)
	logf("collect: %s connected (source %q, netcap %s)", who, hello.Source, hello.Version)

	for {
		if !s.arm(conn, s.cfg.IdleTimeout) {
			return
		}

		t, payload, err := ReadFrame(conn, s.cfg.MaxFrame)
		if err != nil {
			if errors.Is(err, ErrFrameTooLarge) || errors.Is(err, ErrUnknownFrame) {
				s.sendError(conn, err.Error())
			}
			if !errors.Is(err, io.EOF) {
				logf("collect: %s: read: %v", who, err)
			}

			return
		}

		if t != FrameBatch {
			logf("collect: %s: unexpected frame type %d", who, t)
			s.sendError(conn, fmt.Sprintf("unexpected frame type %d", t))

			return
		}

		seq, reject, err := s.writeBatch(client, hello, sess, payload)
		if reject != "" {
			// The batch is bad and will be bad on resend: tell the agent to drop it.
			logf("collect: %s: rejected batch: %s", who, reject)
			s.sendError(conn, reject)

			return
		}
		if err != nil {
			// A local failure: close without an Error frame so the agent resends.
			logf("collect: %s: write: %v", who, err)

			return
		}

		if err = s.send(conn, FrameAck, EncodeAck(seq)); err != nil {
			logf("collect: %s: ack: %v", who, err)

			return
		}
	}
}

func (s *Server) readHello(conn net.Conn) (*types.AgentHello, error) {
	if !s.arm(conn, s.cfg.HandshakeTimeout) {
		return nil, ErrServerClosed
	}

	t, payload, err := ReadFrame(conn, 4096)
	if err != nil {
		return nil, err
	}
	if t != FrameHello {
		return nil, fmt.Errorf("expected hello, got frame type %d", t)
	}

	hello := new(types.AgentHello)
	if err = proto.Unmarshal(payload, hello); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if hello.ProtocolVersion != ProtocolVersion {
		return nil, fmt.Errorf("protocol version %d not supported, want %d", hello.ProtocolVersion, ProtocolVersion)
	}

	return hello, nil
}

// writeBatch decodes, validates and writes one batch. reject is set when the
// batch itself is invalid; err when writing failed locally.
func (s *Server) writeBatch(client string, hello *types.AgentHello, sess *session, payload []byte) (seq uint64, reject string, err error) {
	b := new(types.Batch)
	if err = proto.Unmarshal(payload, b); err != nil {
		return 0, "decode batch: " + err.Error(), nil
	}
	if b.Seq == 0 {
		return 0, "batch sequence number 0", nil
	}

	n, err := CountRecords(b.MessageType, b.Data)
	if err != nil {
		return b.Seq, fmt.Sprintf("batch %d (%s): %v", b.Seq, b.MessageType, err), nil
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()

	sess.used = time.Now()
	if b.Seq <= sess.lastSeq {
		return b.Seq, "", nil // already written; the ack was lost
	}

	if n > 0 {
		if err = s.cfg.Sink.Write(client, hello, b, n); err != nil {
			return b.Seq, "", err
		}
	}
	sess.lastSeq = b.Seq

	return b.Seq, "", nil
}

func (s *Server) session(client string, id uint64) *session {
	s.mu.Lock()
	defer s.mu.Unlock()

	m := s.sessions[client]
	if m == nil {
		m = map[uint64]*session{}
		s.sessions[client] = m
	}

	if sess, ok := m[id]; ok {
		return sess
	}

	if len(m) >= maxSessionsPerClient {
		var (
			oldest   uint64
			oldestAt time.Time
		)
		for k, v := range m {
			v.mu.Lock()
			used := v.used
			v.mu.Unlock()
			if oldestAt.IsZero() || used.Before(oldestAt) {
				oldest, oldestAt = k, used
			}
		}
		delete(m, oldest)
	}

	sess := &session{used: time.Now()}
	m[id] = sess

	return sess
}

// arm sets the read deadline for the next read and reports whether to go on.
// Checking closing after setting it means Shutdown's own deadline either
// comes later and wins, or this check sees closing.
func (s *Server) arm(conn net.Conn, d time.Duration) bool {
	_ = conn.SetReadDeadline(time.Now().Add(d))

	s.mu.Lock()
	defer s.mu.Unlock()

	return !s.closing
}

func (s *Server) send(conn net.Conn, t byte, payload []byte) error {
	_ = conn.SetWriteDeadline(time.Now().Add(s.cfg.WriteTimeout))

	return WriteFrame(conn, t, payload)
}

func (s *Server) sendError(conn net.Conn, reason string) {
	_ = s.send(conn, FrameError, []byte(reason))
}
