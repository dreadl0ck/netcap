package gateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/dreadl0ck/netcap/internal/policy"
)

const maxModbusADU = 260

var errModbus = errors.New("gateway: invalid or unsupported Modbus frame")

// Serve owns and closes l. Cancellation closes active connections and waits for
// all handlers. Each client has at most one upstream connection and outstanding ADU.
func (g *Gateway) Serve(ctx context.Context, l net.Listener) error {
	defer l.Close()
	if g.cfg.Protocol == "dns" {
		return protocolError(g.cfg.Protocol)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = l.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	// Cancel before waiting, including on unexpected listener errors.
	defer cancel()
	slots := g.slots
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		ip, ok := g.clientAllowed(c.RemoteAddr())
		if !ok {
			_ = c.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
			wg.Add(1)
			go func() { defer wg.Done(); defer func() { <-slots }(); g.serveClient(ctx, c, ip) }()
		default:
			_ = c.Close()
		}
	}
}

func (g *Gateway) modbusClient(parent context.Context, client net.Conn, ip string) {
	defer client.Close()
	ctx, cancel := context.WithTimeout(parent, g.cfg.SessionTimeout)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stop()
	var upstream net.Conn
	for i := 0; ctx.Err() == nil && i < g.cfg.MaxSessionMessages; i++ {
		req, err := g.readModbus(ctx, client, true)
		if err != nil {
			return
		}
		meta, err := parseModbusRequest(req)
		if err != nil {
			return
		}
		e := policy.Event{Protocol: "modbus", Modbus: meta, ClientIP: ip, Phase: "request"}
		if !g.allowed(e) {
			if g.writeFrame(ctx, client, modbusException(req, 1)) != nil {
				return
			}
			continue
		}
		// No upstream connection or request bytes exist before request authorization.
		if upstream == nil {
			upstream, err = g.dial(ctx)
			if err != nil {
				_ = g.writeFrame(ctx, client, modbusException(req, 11))
				return
			}
			defer upstream.Close()
			stopUpstream := context.AfterFunc(ctx, func() { _ = upstream.Close() })
			defer stopUpstream()
		}
		if g.writeFrame(ctx, upstream, req) != nil {
			return
		}
		resp, err := g.readModbus(ctx, upstream, false)
		if err != nil || validateModbusResponse(req, resp, meta) != nil {
			return
		}
		e.Phase = "response"
		// Response enforcement cannot undo an upstream write; protect write ranges
		// with request-phase rules.
		if !g.allowed(e) {
			resp = modbusException(req, 1)
		}
		if g.writeFrame(ctx, client, resp) != nil {
			return
		}
	}
}

func (g *Gateway) readModbus(ctx context.Context, c net.Conn, idle bool) ([]byte, error) {
	var header [7]byte
	wait := g.cfg.IOTimeout
	if idle {
		wait = g.cfg.IdleTimeout
	}
	if err := c.SetReadDeadline(deadline(ctx, wait)); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(c, header[:1]); err != nil {
		return nil, err
	}
	if err := c.SetReadDeadline(deadline(ctx, g.cfg.IOTimeout)); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(c, header[1:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(header[4:6]))
	if binary.BigEndian.Uint16(header[2:4]) != 0 || n < 2 || n > 254 {
		return nil, errModbus
	}
	frame := make([]byte, 6+n)
	copy(frame, header[:])
	_, err := io.ReadFull(c, frame[7:])
	return frame, err
}

func (g *Gateway) writeFrame(ctx context.Context, c net.Conn, b []byte) error {
	if err := c.SetWriteDeadline(deadline(ctx, g.cfg.IOTimeout)); err != nil {
		return err
	}
	for len(b) > 0 {
		n, err := c.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

func word(b []byte) int { return int(binary.BigEndian.Uint16(b)) }

func validRange(address, quantity, max int) bool {
	return quantity >= 1 && quantity <= max && address+quantity <= 65536
}

// Only FC1-6,15,16,22,23 are supported. Unit zero/broadcast and reserved units
// are rejected. Quantities and byte counts follow the Modbus application spec.
func parseModbusRequest(frame []byte) (policy.ModbusEvent, error) {
	var m policy.ModbusEvent
	if len(frame) < 8 || len(frame) > maxModbusADU || word(frame[2:4]) != 0 || word(frame[4:6]) != len(frame)-6 || frame[6] < 1 || frame[6] > 247 {
		return m, errModbus
	}
	p := frame[7:]
	m.Function, m.UnitID = int(p[0]), int(frame[6])
	if len(p) < 5 {
		return m, errModbus
	}
	m.Address, m.Quantity = word(p[1:3]), word(p[3:5])
	switch m.Function {
	case 1, 2, 3, 4:
		max := 125
		if m.Function <= 2 {
			max = 2000
		}
		if len(p) != 5 || !validRange(m.Address, m.Quantity, max) {
			return m, errModbus
		}
	case 5, 6:
		if len(p) != 5 || (m.Function == 5 && m.Quantity != 0 && m.Quantity != 0xff00) {
			return m, errModbus
		}
		m.Quantity, m.IsWrite = 1, true
	case 15, 16:
		max := 123
		if m.Function == 15 {
			max = 1968
		}
		if len(p) < 6 || !validRange(m.Address, m.Quantity, max) {
			return m, errModbus
		}
		count := m.Quantity * 2
		if m.Function == 15 {
			count = (m.Quantity + 7) / 8
		}
		if int(p[5]) != count || len(p) != 6+count {
			return m, errModbus
		}
		// Unused coil bits must be zero, avoiding alternate encodings.
		if m.Function == 15 && m.Quantity%8 != 0 && p[len(p)-1]>>uint(m.Quantity%8) != 0 {
			return m, errModbus
		}
		m.IsWrite = true
	case 22:
		if len(p) != 7 {
			return m, errModbus
		}
		m.Quantity, m.IsWrite = 1, true
	case 23:
		if len(p) < 10 {
			return m, errModbus
		}
		m.ReadAddress, m.ReadQuantity = m.Address, m.Quantity
		m.Address, m.Quantity = word(p[5:7]), word(p[7:9])
		if !validRange(m.ReadAddress, m.ReadQuantity, 125) || !validRange(m.Address, m.Quantity, 121) || int(p[9]) != 2*m.Quantity || len(p) != 10+2*m.Quantity {
			return m, errModbus
		}
		m.IsWrite = true
	default:
		return m, errModbus
	}
	m.EndAddress = m.Address + m.Quantity - 1
	if !m.IsWrite {
		m.ReadAddress, m.ReadQuantity = m.Address, m.Quantity
	}
	if m.ReadQuantity > 0 {
		m.ReadEndAddress = m.ReadAddress + m.ReadQuantity - 1
	}
	return m, nil
}

func modbusException(req []byte, code byte) []byte {
	r := append([]byte(nil), req[:7]...)
	r[4], r[5] = 0, 3
	return append(r, req[7]|0x80, code)
}

func validateModbusResponse(req, resp []byte, m policy.ModbusEvent) error {
	if len(resp) < 8 || len(resp) > maxModbusADU || !bytes.Equal(req[:4], resp[:4]) || req[6] != resp[6] || word(resp[4:6]) != len(resp)-6 {
		return errModbus
	}
	p := resp[7:]
	if p[0] == req[7]|0x80 {
		if len(p) != 2 {
			return errModbus
		}
		switch p[1] {
		case 1, 2, 3, 4, 5, 6, 8, 10, 11:
			return nil
		default:
			return errModbus
		}
	}
	if p[0] != req[7] {
		return errModbus
	}
	switch m.Function {
	case 1, 2, 3, 4, 23:
		count := m.ReadQuantity * 2
		if m.Function <= 2 {
			count = (m.ReadQuantity + 7) / 8
		}
		if len(p) != count+2 || int(p[1]) != count {
			return errModbus
		}
		if m.Function <= 2 && m.ReadQuantity%8 != 0 && p[len(p)-1]>>uint(m.ReadQuantity%8) != 0 {
			return errModbus
		}
	case 5, 6, 22:
		if !bytes.Equal(req[7:], p) {
			return errModbus
		}
	case 15, 16:
		if len(p) != 5 || !bytes.Equal(req[7:12], p) {
			return errModbus
		}
	default:
		return errModbus
	}
	return nil
}
