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
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

// ClientConfig configures an agent Client.
type ClientConfig struct {
	Addr              string
	Identity          tls.Certificate
	ServerFingerprint string
	Hello             types.AgentHello // ProtocolVersion and Session are filled in

	MaxPending  int           // bytes of unacknowledged batches kept for resend, default 64 MiB
	DialTimeout time.Duration // default 10s
	AckTimeout  time.Duration // default 60s
	MinBackoff  time.Duration // default 1s
	MaxBackoff  time.Duration // default 60s

	Logger *log.Logger // default log.Default()
}

// ClientStats counts what happened to enqueued batches.
type ClientStats struct {
	Acked    uint64 // written by the collector
	Dropped  uint64 // evicted because MaxPending was exceeded
	Rejected uint64 // refused by the collector as invalid
	Pending  int    // still queued
}

// Client delivers batches to a collector over one TLS connection, waits for
// each to be acknowledged, and reconnects with backoff when the connection
// drops. Unacknowledged batches are kept in memory and resent.
type Client struct {
	cfg   ClientConfig
	tls   *tls.Config
	wake  chan struct{}
	done  chan struct{}
	abort chan struct{} // closed when Close gives up waiting

	mu           sync.Mutex
	queue        []*types.Batch
	pendingBytes int
	seq          uint64
	closing      bool
	stats        ClientStats

	conn net.Conn // owned by run
}

// NewClient validates cfg and starts the sender goroutine.
func NewClient(cfg ClientConfig) (*Client, error) {
	tlsConf, err := ClientTLSConfig(cfg.Identity, cfg.ServerFingerprint)
	if err != nil {
		return nil, err
	}
	if cfg.MaxPending <= 0 {
		cfg.MaxPending = 64 << 20
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if cfg.AckTimeout <= 0 {
		cfg.AckTimeout = 60 * time.Second
	}
	if cfg.MinBackoff <= 0 {
		cfg.MinBackoff = time.Second
	}
	if cfg.MaxBackoff < cfg.MinBackoff {
		cfg.MaxBackoff = max(60*time.Second, cfg.MinBackoff)
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}

	var sid [8]byte
	if _, err = rand.Read(sid[:]); err != nil {
		return nil, err
	}
	cfg.Hello.ProtocolVersion = ProtocolVersion
	cfg.Hello.Session = binary.BigEndian.Uint64(sid[:])

	c := &Client{
		cfg:   cfg,
		tls:   tlsConf,
		wake:  make(chan struct{}, 1),
		done:  make(chan struct{}),
		abort: make(chan struct{}),
	}

	go c.run()

	return c, nil
}

// Enqueue assigns b a sequence number and queues it. It never blocks; when the
// queue exceeds MaxPending the oldest batches are dropped and counted.
func (c *Client) Enqueue(b *types.Batch) error {
	c.mu.Lock()

	if c.closing {
		c.mu.Unlock()

		return errors.New("client closing")
	}

	c.seq++
	b.Seq = c.seq
	c.queue = append(c.queue, b)
	c.pendingBytes += len(b.Data)

	// Keep the head: it may be in flight, and run removes it by identity.
	var dropped int
	for c.pendingBytes > c.cfg.MaxPending && len(c.queue) > 2 {
		victim := c.queue[1]
		c.queue = append(c.queue[:1], c.queue[2:]...)
		c.pendingBytes -= len(victim.Data)
		c.stats.Dropped++
		dropped++
	}
	c.mu.Unlock()

	if dropped > 0 {
		c.cfg.Logger.Printf("agent: collector backlog over %d bytes, dropped %d oldest batches", c.cfg.MaxPending, dropped)
	}

	c.signal()

	return nil
}

func (c *Client) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// Stats returns a snapshot of the delivery counters.
func (c *Client) Stats() ClientStats {
	c.mu.Lock()
	defer c.mu.Unlock()

	s := c.stats
	s.Pending = len(c.queue)

	return s
}

// Close stops accepting batches and waits until the queue is delivered or ctx
// ends. It returns the final stats; Pending > 0 means batches were not delivered.
func (c *Client) Close(ctx context.Context) (ClientStats, error) {
	c.mu.Lock()
	c.closing = true
	c.mu.Unlock()
	c.signal()

	var err error
	select {
	case <-c.done:
	case <-ctx.Done():
		err = ctx.Err()
		close(c.abort)
		c.mu.Lock()
		if c.conn != nil {
			_ = c.conn.Close() // unblock a pending ack read
		}
		c.mu.Unlock()
		<-c.done
	}

	return c.Stats(), err
}

func (c *Client) head() (b *types.Batch, finished bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.queue) > 0 {
		return c.queue[0], false
	}

	return nil, c.closing
}

func (c *Client) pop(b *types.Batch, rejected bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.queue) == 0 || c.queue[0] != b {
		return
	}

	c.queue[0] = nil
	c.queue = c.queue[1:]
	c.pendingBytes -= len(b.Data)

	if rejected {
		c.stats.Rejected++
	} else {
		c.stats.Acked++
	}
}

func (c *Client) aborted() bool {
	select {
	case <-c.abort:
		return true
	default:
		return false
	}
}

// run is the only goroutine that opens connections and sends on them.
func (c *Client) run() {
	defer close(c.done)
	defer c.disconnect()

	backoff := c.cfg.MinBackoff

	for !c.aborted() {
		b, finished := c.head()
		if finished {
			return
		}
		if b == nil {
			select {
			case <-c.wake:
			case <-c.abort:
			}

			continue
		}

		err := c.deliver(b)
		if err == nil {
			backoff = c.cfg.MinBackoff

			continue
		}

		var rej *rejectedError
		if errors.As(err, &rej) {
			// The collector closes the connection after an Error frame.
			c.cfg.Logger.Printf("agent: collector rejected batch %d (%s), dropping it: %s", b.Seq, b.MessageType, rej.reason)
			c.pop(b, true)
			c.disconnect()

			continue
		}

		c.disconnect()
		if c.aborted() {
			return
		}

		c.cfg.Logger.Printf("agent: delivery to %s failed, retrying in ~%s: %v", c.cfg.Addr, backoff, err)
		c.sleep(backoff)
		backoff = min(2*backoff, c.cfg.MaxBackoff)
	}
}

// sleep waits about d (±10% jitter) or until Close gives up.
func (c *Client) sleep(d time.Duration) {
	if j, err := rand.Int(rand.Reader, big.NewInt(int64(d)/5+1)); err == nil {
		d = d - d/10 + time.Duration(j.Int64())
	}

	t := time.NewTimer(d)
	defer t.Stop()

	select {
	case <-t.C:
	case <-c.abort:
	}
}

type rejectedError struct{ reason string }

func (e *rejectedError) Error() string { return "rejected: " + e.reason }

func (c *Client) deliver(b *types.Batch) error {
	conn, err := c.connect()
	if err != nil {
		return err
	}

	payload, err := proto.Marshal(b)
	if err != nil {
		return &rejectedError{reason: "marshal: " + err.Error()}
	}
	if len(payload) > DefaultMaxFrame {
		return &rejectedError{reason: fmt.Sprintf("batch is %d bytes, over the %d byte frame limit", len(payload), DefaultMaxFrame)}
	}

	_ = conn.SetDeadline(time.Now().Add(c.cfg.AckTimeout))
	if err = WriteFrame(conn, FrameBatch, payload); err != nil {
		return err
	}

	seq, err := c.readAck(conn)
	if err != nil {
		return err
	}
	if seq != b.Seq {
		return fmt.Errorf("ack for batch %d, sent %d", seq, b.Seq)
	}

	c.pop(b, false)

	return nil
}

func (c *Client) readAck(conn net.Conn) (uint64, error) {
	t, p, err := ReadFrame(conn, 64<<10)
	if err != nil {
		return 0, err
	}

	switch t {
	case FrameAck:
		return DecodeAck(p)
	case FrameError:
		return 0, &rejectedError{reason: string(p)}
	default:
		return 0, fmt.Errorf("unexpected frame type %d", t)
	}
}

func (c *Client) connect() (net.Conn, error) {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		return conn, nil
	}

	d := &net.Dialer{Timeout: c.cfg.DialTimeout, KeepAlive: 30 * time.Second}

	raw, err := d.Dial("tcp", c.cfg.Addr)
	if err != nil {
		return nil, err
	}

	tc := tls.Client(raw, c.tls)
	_ = tc.SetDeadline(time.Now().Add(c.cfg.DialTimeout))
	if err = tc.Handshake(); err != nil {
		_ = raw.Close()

		return nil, fmt.Errorf("tls: %w", err)
	}

	hello, err := proto.Marshal(&c.cfg.Hello)
	if err != nil {
		_ = tc.Close()

		return nil, err
	}
	if err = WriteFrame(tc, FrameHello, hello); err != nil {
		_ = tc.Close()

		return nil, err
	}

	_ = tc.SetDeadline(time.Now().Add(c.cfg.AckTimeout))
	if _, err = c.readAck(tc); err != nil {
		_ = tc.Close()

		// A refused hello (version mismatch) is retried, never a reason to drop a batch.
		var rej *rejectedError
		if errors.As(err, &rej) {
			return nil, fmt.Errorf("collector refused hello: %s", rej.reason)
		}

		return nil, fmt.Errorf("hello: %w", err)
	}

	c.mu.Lock()
	c.conn = tc
	c.mu.Unlock()
	c.cfg.Logger.Printf("agent: connected to %s", c.cfg.Addr)

	return tc, nil
}

func (c *Client) disconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
}
