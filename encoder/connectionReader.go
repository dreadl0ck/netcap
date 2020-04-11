package encoder

import (
	"github.com/dreadl0ck/gopacket"
	"sync"
)

// ConnectionReader is an interface for processing a bidirectional stream of network data
type ConnectionReader interface {
	Read(p []byte) (int, error)
	Run(wg *sync.WaitGroup)
	BytesChan() chan []byte
	Cleanup(wg *sync.WaitGroup, s2c Connection, c2s Connection)
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
