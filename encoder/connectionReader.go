package encoder

import (
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/netcap/reassembly"
)

// Data is a fragment of data we received from a StreamReader
// its contains the raw bytes as well an assembler context with timestamp information
type Data struct {
	raw []byte
	ac  reassembly.AssemblerContext
	dir reassembly.TCPFlowDirection
}

// DataSlice implements sort.Inferface to sort data fragments based on their timestamps
type DataSlice []*Data

func (d DataSlice) Len() int {
	return len(d)
}
func (d DataSlice) Less(i, j int) bool {
	return d[i].ac.GetCaptureInfo().Timestamp.Before(d[j].ac.GetCaptureInfo().Timestamp)
}
func (d DataSlice) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}

// ConnectionReader is an interface for processing a bidirectional stream of network data
type ConnectionReader interface {
	Read(p []byte) (int, error)
	Run(f *tcpConnectionFactory)
	DataChan() chan *Data
	DataSlice() DataSlice
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
