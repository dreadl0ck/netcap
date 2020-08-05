package decoder

import (
	"bytes"
	"time"

	"github.com/dreadl0ck/gopacket"

	"github.com/dreadl0ck/netcap/reassembly"
)

// StreamReader is an interface for processing a uni-directional stream of network data
// it defines to manage a stream lifecycle and is used to close the remaining open streams
// and process the remaining data when the engine is stopped
type StreamReader interface {
	Read(p []byte) (int, error)
	Run(f *tcpConnectionFactory)
	DataChan() chan *StreamData
	DataSlice() StreamDataSlice
	Cleanup(f *tcpConnectionFactory)

	ClientStream() []byte
	ServerStream() []byte

	IsClient() bool
	SetClient(bool)
	Ident() string
	Network() gopacket.Flow
	Transport() gopacket.Flow
	FirstPacket() time.Time
	Saved() bool
	NumBytes() int
	Client() StreamReader
	ServiceBanner() []byte
	MarkSaved()
	ServiceIdent() string

	// util functions that provide access to the entire stream via parent
	ConversationRaw() []byte
	ConversationColored() []byte

	// sort all stream fragments based on their timestamp
	// and generate the conversation buffers
	SortAndMergeFragments()
}

// StreamDecoder is the interface for processing a bi-directional network connection
type StreamDecoder interface {
	Decode(s2c Stream, c2s Stream)
}

// StreamData is a fragment of data we received from a StreamReader
// its contains the raw bytes as well an assembler context with timestamp information
type StreamData struct {
	raw []byte
	ac  reassembly.AssemblerContext
	dir reassembly.TCPFlowDirection
}

// StreamDataSlice implements sort.Interface to sort data fragments based on their timestamps
type StreamDataSlice []*StreamData

func (d StreamDataSlice) Bytes() []byte {
	var b bytes.Buffer
	for _, data := range d {
		b.Write(data.raw)
	}
	return b.Bytes()
}

func (d StreamDataSlice) Len() int {
	return len(d)
}

func (d StreamDataSlice) Less(i, j int) bool {
	data1 := d[i]
	data2 := d[j]
	if data1.ac == nil || data2.ac == nil {
		return false
	}
	return data1.ac.GetCaptureInfo().Timestamp.Before(data2.ac.GetCaptureInfo().Timestamp)
}

func (d StreamDataSlice) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}

// Stream contains both flows for a connection
type Stream struct {
	a gopacket.Flow
	b gopacket.Flow
}

// Reverse flips source and destination
func (s Stream) Reverse() Stream {
	return Stream{
		s.a.Reverse(),
		s.b.Reverse(),
	}
}

func (s Stream) String() string {
	return s.a.String() + " : " + s.b.String()
}
