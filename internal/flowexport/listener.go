package flowexport

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"
)

// Receive uses the same decoder and recorder as passive capture. The caller owns conn.
func Receive(ctx context.Context, conn *net.UDPConn, recorder *Recorder) error {
	buffer := make([]byte, 65535)
	local := conn.LocalAddr().(*net.UDPAddr).AddrPort()
	var ordinal uint64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
			return err
		}
		n, remote, err := conn.ReadFromUDPAddrPort(buffer)
		if err != nil {
			var networkError net.Error
			if errors.As(err, &networkError) && networkError.Timeout() {
				continue
			}
			return err
		}
		env := Envelope{Exporter: netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port()).String(), Collector: netip.AddrPortFrom(local.Addr().Unmap(), local.Port()).String(), ReceivedNs: time.Now().UnixNano(), PacketOrdinal: ordinal}
		ordinal++
		if err := recorder.Observe(buffer[:n], env); err != nil {
			return err
		}
		if err := recorder.Flush(); err != nil {
			return err
		}
	}
}
