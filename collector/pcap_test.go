package collector

import (
	"os"
	"testing"

	"github.com/google/gopacket/pcapgo"
)

var ngFile = "../pcaps/Monday-WorkingHours.pcapng"
var pcapFile = "../pcaps/maccdc2012_00000.pcap"

func BenchmarkReadPcapNG(b *testing.B) {

	r, f, err := openPcapNG(ngFile)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
	}
}

func BenchmarkReadPcapNGZeroCopy(b *testing.B) {

	r, f, err := openPcapNG(ngFile)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_, _, err := r.ZeroCopyReadPacketData()
		if err != nil {
			break
		}
	}
}

func openPcapFile(file string) (*pcapgo.Reader, *os.File) {

	// get file handle
	f, err := os.Open(file)
	if err != nil {
		panic(err)
	}

	// try to create pcap reader
	r, err := pcapgo.NewReader(f)
	if err != nil {
		panic(err)
	}

	return r, f
}

func BenchmarkReadPcap(b *testing.B) {

	r, f := openPcapFile(pcapFile)
	defer f.Close()

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
	}
}
