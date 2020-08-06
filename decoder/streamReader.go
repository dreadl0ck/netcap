package decoder

import (
	"bytes"
	"time"

	"github.com/dreadl0ck/gopacket"

	"github.com/dreadl0ck/netcap/reassembly"
)

// streamReader is an interface for processing a uni-directional stream of network data
// it defines to manage a stream lifecycle and is used to close the remaining open streams
// and process the remaining data when the engine is stopped
type streamReader interface {
	Read(p []byte) (int, error)
	Run(f *tcpConnectionFactory)
	DataChan() chan *streamData
	DataSlice() streamDataSlice
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
	Client() streamReader
	ServiceBanner() []byte
	MarkSaved()
	ServiceIdent() string

	// ConversationRaw is a util function that provides access to the entire stream via parent
	ConversationRaw() []byte
	ConversationColored() []byte

	// SortAndMergeFragments sorts all stream fragments based on their timestamp
	// and generate the conversation buffers
	SortAndMergeFragments()
}

// streamDecoder is the interface for processing a bi-directional network connection
type streamDecoder interface {
	Decode()
}

// streamData is a fragment of data we received from a streamReader
// its contains the raw bytes as well an assembler context with timestamp information
type streamData struct {
	raw []byte
	ac  reassembly.AssemblerContext
	dir reassembly.TCPFlowDirection
}

// streamDataSlice implements sort.Interface to sort data fragments based on their timestamps
type streamDataSlice []*streamData

func (d streamDataSlice) bytes() []byte {
	var b bytes.Buffer
	for _, data := range d {
		b.Write(data.raw)
	}
	return b.Bytes()
}

func (d streamDataSlice) Len() int {
	return len(d)
}

func (d streamDataSlice) Less(i, j int) bool {
	data1 := d[i]
	data2 := d[j]
	if data1.ac == nil || data2.ac == nil {
		return false
	}
	return data1.ac.GetCaptureInfo().Timestamp.Before(data2.ac.GetCaptureInfo().Timestamp)
}

func (d streamDataSlice) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}

// stream contains both flows for a connection
type stream struct {
	a gopacket.Flow
	b gopacket.Flow
}

// reverse flips source and destination
func (s stream) reverse() stream {
	return stream{
		s.a.Reverse(),
		s.b.Reverse(),
	}
}

func (s stream) String() string {
	return s.a.String() + " : " + s.b.String()
}
