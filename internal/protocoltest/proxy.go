package protocoltest

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

type Mutation struct {
	Direction         string `json:"direction"`
	Frame             int    `json:"frame"`
	Offset            int    `json:"offset"`
	Delete            int    `json:"delete"`
	Insert            []byte `json:"insert"`
	RepairLength      bool   `json:"repairLength"`
	Drop              bool   `json:"drop"`
	Copies            int    `json:"copies"`
	DelayMilliseconds int    `json:"delayMilliseconds"`
}

type Proxy struct {
	Address             string     `json:"address"`
	Framing             Framing    `json:"framing"`
	TimeoutMilliseconds int        `json:"timeoutMilliseconds"`
	MaxFrames           int        `json:"maxFrames"`
	MaxTotalBytes       int        `json:"maxTotalBytes"`
	Mutations           []Mutation `json:"mutations"`
}

type ProxyObservation struct {
	Direction   string `json:"direction"`
	Frame       int    `json:"frame"`
	Original    []byte `json:"original"`
	Transmitted []byte `json:"transmitted"`
	Copies      int    `json:"copies"`
	TimestampNs string `json:"timestampNs"`
	Error       string `json:"error,omitempty"`
}

func MutateFrame(frame []byte, framing Framing, mutation Mutation) ([]byte, error) {
	if err := framing.Validate(); err != nil {
		return nil, err
	}
	if mutation.Offset < 0 || mutation.Offset > len(frame) || mutation.Delete < 0 || mutation.Delete > len(frame)-mutation.Offset {
		return nil, fmt.Errorf("mutation outside frame bounds")
	}
	length := len(frame) - mutation.Delete + len(mutation.Insert)
	if length > framing.MaxBytes {
		return nil, fmt.Errorf("mutated frame exceeds budget")
	}
	data := make([]byte, 0, length)
	data = append(data, frame[:mutation.Offset]...)
	data = append(data, mutation.Insert...)
	data = append(data, frame[mutation.Offset+mutation.Delete:]...)
	if mutation.RepairLength {
		if framing.Kind != "length-prefix" || len(data) < framing.LengthBytes {
			return nil, fmt.Errorf("length repair requires intact length-prefix framing")
		}
		n := len(data)
		if !framing.LengthIncludesHeader {
			n -= framing.LengthBytes
		}
		var order binary.ByteOrder = binary.BigEndian
		if framing.ByteOrder == "little" {
			order = binary.LittleEndian
		}
		switch framing.LengthBytes {
		case 1:
			if n > 255 {
				return nil, fmt.Errorf("repaired length overflows uint8")
			}
			data[0] = byte(n)
		case 2:
			if n > 65535 {
				return nil, fmt.Errorf("repaired length overflows uint16")
			}
			order.PutUint16(data, uint16(n))
		case 4:
			order.PutUint32(data, uint32(n))
		}
	}
	return data, nil
}

// ProxyOne handles one accepted TCP connection. The caller owns listener.
// It terminates both legs on framing, mutation, budget, timeout or transport failure.
func ProxyOne(ctx context.Context, listener net.Listener, spec Proxy) ([]ProxyObservation, error) {
	if err := spec.Framing.Validate(); err != nil {
		return nil, err
	}
	if spec.MaxFrames < 1 || spec.MaxFrames > 10000 || spec.MaxTotalBytes < 1 || spec.MaxTotalBytes > 16<<20 || spec.TimeoutMilliseconds < 1 || spec.TimeoutMilliseconds > 300000 {
		return nil, fmt.Errorf("invalid proxy limits")
	}
	if len(spec.Mutations) > 256 {
		return nil, fmt.Errorf("mutation limit exceeded")
	}
	for _, m := range spec.Mutations {
		if (m.Direction != "client" && m.Direction != "server") || m.Frame < 0 || m.Copies < 0 || m.Copies > 8 || m.DelayMilliseconds < 0 || m.DelayMilliseconds > 30000 {
			return nil, fmt.Errorf("invalid mutation selector/action")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(spec.TimeoutMilliseconds)*time.Millisecond)
	defer cancel()
	stopAccept := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stopAccept()
	client, err := listener.Accept()
	if err != nil {
		return nil, err
	}
	defer client.Close()
	dialer := net.Dialer{}
	server, err := dialer.DialContext(ctx, "tcp", spec.Address)
	if err != nil {
		return nil, err
	}
	defer server.Close()
	stop := context.AfterFunc(ctx, func() { _ = client.Close(); _ = server.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := client.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if err := server.SetDeadline(deadline); err != nil {
		return nil, err
	}
	var mu sync.Mutex
	observations := []ProxyObservation{}
	total, frames := 0, 0
	done := make(chan error, 2)
	transfer := func(direction string, src, dst net.Conn) {
		for index := 0; ; index++ {
			frame, err := spec.Framing.Read(src)
			if err == io.EOF && len(frame) == 0 {
				if tcp, ok := dst.(*net.TCPConn); ok {
					_ = tcp.CloseWrite()
				}
				done <- nil
				return
			}
			if err != nil {
				mu.Lock()
				if len(frame) <= spec.MaxTotalBytes-total && frames < spec.MaxFrames {
					total += len(frame)
					frames++
					observations = append(observations, ProxyObservation{Direction: direction, Frame: index, Original: append([]byte(nil), frame...), TimestampNs: fmt.Sprint(time.Now().UnixNano()), Error: err.Error()})
				}
				mu.Unlock()
				done <- err
				return
			}
			data := frame
			copies := 1
			delay := 0
			for _, mutation := range spec.Mutations {
				if mutation.Direction != direction || mutation.Frame != index {
					continue
				}
				data, err = MutateFrame(data, spec.Framing, mutation)
				if err != nil {
					done <- err
					return
				}
				if mutation.Drop {
					copies = 0
				} else if mutation.Copies > 0 {
					copies = mutation.Copies
				}
				delay += mutation.DelayMilliseconds
			}
			mu.Lock()
			cost := len(frame) + len(data)*copies
			if cost > spec.MaxTotalBytes-total || frames >= spec.MaxFrames {
				mu.Unlock()
				done <- fmt.Errorf("proxy evidence budget exceeded")
				return
			}
			total += cost
			frames++
			mu.Unlock()
			if delay > 0 {
				timer := time.NewTimer(time.Duration(delay) * time.Millisecond)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					done <- ctx.Err()
					return
				}
			}
			transmitted := make([]byte, 0, len(data)*copies)
			for copy := 0; copy < copies; copy++ {
				for offset := 0; offset < len(data); {
					n, werr := dst.Write(data[offset:])
					transmitted = append(transmitted, data[offset:offset+n]...)
					offset += n
					if werr != nil {
						err = werr
						break
					}
					if n == 0 {
						err = io.ErrShortWrite
						break
					}
				}
				if err != nil {
					break
				}
			}
			mu.Lock()
			observations = append(observations, ProxyObservation{Direction: direction, Frame: index, Original: append([]byte(nil), frame...), Transmitted: transmitted, Copies: copies, TimestampNs: fmt.Sprint(time.Now().UnixNano())})
			mu.Unlock()
			if err != nil {
				done <- err
				return
			}
		}
	}
	go transfer("client", client, server)
	go transfer("server", server, client)
	first := <-done
	if first != nil {
		cancel()
	}
	second := <-done
	if first != nil {
		return observations, first
	}
	if second != nil {
		return observations, second
	}
	return observations, ctx.Err()
}
