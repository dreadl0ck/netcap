package collector

import (
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/dreadl0ck/gopacket/pcapgo"
)

var (
	ngFile   = "../pcaps/Monday-WorkingHours.pcapng"
	pcapFile = "../pcaps/maccdc2012_00000.pcap"
)

func BenchmarkReadPcapNG(b *testing.B) {
	r, f, err := openPcapNG(ngFile)
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		errClose := f.Close()
		if errClose != nil && !errors.Is(errClose, io.EOF) {
			fmt.Println(errClose)
		}
	}()

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_, _, err = r.ReadPacketData()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReadPcapNGZeroCopy(b *testing.B) {
	r, f, err := openPcapNG(ngFile)
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		errClose := f.Close()
		if errClose != nil && !errors.Is(errClose, io.EOF) {
			fmt.Println(errClose)
		}
	}()

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_, _, err = r.ZeroCopyReadPacketData()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func openPcapFile(file string) (*pcapgo.Reader, *os.File, error) {
	// get file handle
	f, err := os.Open(file)
	if err != nil {
		return nil, nil, err
	}

	// try to create pcap reader
	r, err := pcapgo.NewReader(f)
	if err != nil {
		return nil, nil, err
	}

	return r, f, nil
}

func BenchmarkReadPcap(b *testing.B) {
	r, f, err := openPcapFile(pcapFile)
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		errClose := f.Close()
		if errClose != nil && !errors.Is(errClose, io.EOF) {
			fmt.Println(errClose)
		}
	}()

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_, _, err = r.ReadPacketData()
		if err != nil && !errors.Is(err, io.EOF) {
			b.Fatal(err)
		}
	}
}
