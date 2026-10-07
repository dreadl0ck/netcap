package protocoltest

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Passthrough observations are transport chunks, not application frames. TLS
// remains end-to-end: neither keys nor plaintext are available to this mode.
func proxyPassthrough(ctx context.Context, l net.Listener, spec Proxy) ([]ProxyObservation, error) {
	if spec.TLS != nil || len(spec.Mutations) > 0 || len(spec.Injections) > 0 || spec.Framing.Kind != "" {
		return nil, fmt.Errorf("passthrough forbids TLS termination, framing and mutations")
	}
	if spec.MaxFrames < 1 || spec.MaxFrames > 10000 || spec.MaxTotalBytes < 2 || spec.MaxTotalBytes > 16<<20 || spec.TimeoutMilliseconds < 1 || spec.TimeoutMilliseconds > 300000 {
		return nil, fmt.Errorf("invalid passthrough bounds")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(spec.TimeoutMilliseconds)*time.Millisecond)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = l.Close() })
	defer stop()
	client, err := l.Accept()
	if err != nil {
		return nil, err
	}
	defer client.Close()
	server, err := (&net.Dialer{}).DialContext(ctx, "tcp", spec.Address)
	if err != nil {
		return nil, err
	}
	defer server.Close()
	closeBoth := context.AfterFunc(ctx, func() { _ = client.Close(); _ = server.Close() })
	defer closeBoth()
	deadline, _ := ctx.Deadline()
	if err = client.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if err = server.SetDeadline(deadline); err != nil {
		return nil, err
	}
	var mu sync.Mutex
	total, frames := 0, 0
	obs := []ProxyObservation{}
	done := make(chan error, 2)
	transfer := func(direction string, src, dst net.Conn) {
		buffer := make([]byte, min(16384, spec.MaxTotalBytes/2))
		for index := 0; ; index++ {
			n, readErr := src.Read(buffer)
			if n > 0 {
				mu.Lock()
				if 2*n > spec.MaxTotalBytes-total || frames >= spec.MaxFrames {
					mu.Unlock()
					done <- fmt.Errorf("passthrough evidence budget exceeded")
					return
				}
				total += 2 * n
				frames++
				mu.Unlock()
				o := ProxyObservation{Direction: direction, Frame: index, Original: append([]byte{}, buffer[:n]...), Copies: 1, TimestampNs: fmt.Sprint(time.Now().UnixNano())}
				for offset := 0; offset < n; {
					written, e := dst.Write(buffer[offset:n])
					o.Transmitted = append(o.Transmitted, buffer[offset:offset+written]...)
					offset += written
					if e == nil && written == 0 {
						e = io.ErrShortWrite
					}
					if e != nil {
						o.Error = e.Error()
						readErr = e
						break
					}
				}
				mu.Lock()
				obs = append(obs, o)
				mu.Unlock()
			}
			if readErr != nil {
				if readErr == io.EOF {
					if half, ok := dst.(interface{ CloseWrite() error }); ok {
						_ = half.CloseWrite()
					}
					readErr = nil
				}
				done <- readErr
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
		return obs, first
	}
	if second != nil {
		return obs, second
	}
	return obs, ctx.Err()
}
