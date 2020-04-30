package encoder

import (
	"github.com/dreadl0ck/gopacket"
)

// ConnectionReader is an interface for processing a bidirectional stream of network data
type ConnectionReader interface {
	Read(p []byte) (int, error)
	Run(f *tcpConnectionFactory)
	BytesChan() chan []byte
	Cleanup(f *tcpConnectionFactory, s2c Connection, c2s Connection)
}

// Connection contains both unidirectional flows for a connection
type Connection struct {
	a gopacket.Flow
	b gopacket.Flow
}

// Reverse flips source and destination
func (s Connection) Reverse() Connection {
	return Connection{
		s.a.Reverse(),
		s.b.Reverse(),
	}
}

func (s Connection) String() string {
	return s.a.String() + " : " + s.b.String()
}
