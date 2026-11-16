package protobuf

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"testing"

	"github.com/dreadl0ck/netcap/internal/testutil"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestRecheck168RejectsWireValidForeignAutodetection(t *testing.T) {
	ambiguous := 0
	for _, name := range []string{"nbns_refresh_fp.pcap", "nbns_query_fp.pcap", "dns_query_fp.pcap", "dns_response_fp.pcap"} {
		t.Run(name, func(t *testing.T) {
			f, err := os.Open(testutil.Recheck168Capture(t, name))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			reader, err := pcapgo.NewReader(f)
			if err != nil {
				t.Fatal(err)
			}
			payloads := 0
			for {
				data, _, err := reader.ReadPacketData()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				packet := gopacket.NewPacket(data, reader.LinkType(), gopacket.Default)
				if layer := packet.Layer(layers.LayerTypeUDP); layer != nil {
					payload := layer.(*layers.UDP).Payload
					payloads++
					if _, err := DecodeMessages(payload); err == nil {
						ambiguous++
					}
					if IsProtobufData(payload) {
						t.Fatal("foreign wire-valid packet claimed as Protobuf")
					}
				}
			}
			if payloads == 0 {
				t.Fatal("fixture lacks UDP payload")
			}
		})
	}
	if ambiguous == 0 {
		t.Fatal("fixture set did not exercise wire-valid ambiguity")
	}
}

func TestProtobufIntentPreservesWeakWireMessages(t *testing.T) {
	weak := []byte{0x09, 1, 2, 3, 4, 5, 6, 7, 8}
	if IsProtobufData(weak) || !ValidConfiguredData(weak) {
		t.Fatal("autodetection and configured decoding are not distinct")
	}
	if !IsProtobufData(validProtobufData) {
		t.Fatal("genuine multi-field control rejected")
	}
	nested := append([]byte{0x0a, byte(len(validProtobufData))}, validProtobufData...)
	if !IsProtobufData(nested) {
		t.Fatal("nested multi-field control rejected")
	}
	var framed bytes.Buffer
	binary.Write(&framed, binary.BigEndian, uint32(len(validProtobufData)))
	framed.Write(validProtobufData)
	if !IsProtobufData(framed.Bytes()) {
		t.Fatal("TCP framing control rejected")
	}
	framed.WriteByte(0xff)
	if ValidConfiguredData(framed.Bytes()) {
		t.Fatal("trailing frame garbage accepted")
	}
}
