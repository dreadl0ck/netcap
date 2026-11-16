package collector

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/linkaudit"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
)

// RFC 8163 Appendix D, complete 547-byte wire example.
const mstpRFC8163 = `
55 ff 22 01 02 02 19 1c 56 2d 83 56 6f 6a 54 54
54 54 54 54 57 54 56 54 d5 50 2d 6a 7b b0 5c 57
b1 8e bd 00 6e f5 51 ac 5d 5c 5f 5e 59 58 5b 5a
45 44 47 46 41 40 43 42 4d 4c 4f 4e 49 48 4b 4a
75 74 77 76 71 70 73 72 7d 7c 7f 7e 79 78 7b 7a
65 64 67 66 61 60 63 62 6d 6c 6f 6e 69 68 6b 6a
15 14 17 16 11 10 13 12 1d 1c 1f 1e 19 18 1b 1a
05 04 07 06 01 00 03 02 0d 0c 0f 0e 09 08 0b 0a
35 34 37 36 31 30 33 32 3d 3c 3f 3e 39 38 3b 3a
25 24 27 26 21 20 23 22 2d 2c 2f 2e 29 28 2b 2a
d5 d4 d7 d6 d1 d0 d3 d2 dd dc df de d9 d8 db da
c5 c4 c7 c6 c1 c0 c3 c2 cd cc cf ce c9 c8 cb ca
f5 f4 f7 f6 f1 f0 f3 f2 fd fc ff fe f9 f8 fb fa
e5 e4 e7 e6 e1 e0 e3 e2 ed ec ef ee e9 e8 eb ea
95 94 97 96 91 90 93 92 9d 9c 9f 9e 99 98 9b 9a
85 84 87 86 81 80 83 82 8d 8c 8f 8e 89 88 8b 8a
b5 b4 b7 b6 b1 b0 b3 b2 bd bc bf be b9 b8 bb ba
a5 a4 a7 a6 a1 a0 a3 a2 ad ac af ae a9 a8 ab aa
ab 54 57 56 51 50 53 52 5d 5c 5f 5e 59 58 5b 5a
45 44 47 46 41 40 43 42 4d 4c 4f 4e 49 48 4b 4a
75 74 77 76 71 70 73 72 7d 7c 7f 7e 79 78 7b 7a
65 64 67 66 61 60 63 62 6d 6c 6f 6e 69 68 6b 6a
15 14 17 16 11 10 13 12 1d 1c 1f 1e 19 18 1b 1a
05 04 07 06 01 00 03 02 0d 0c 0f 0e 09 08 0b 0a
35 34 37 36 31 30 33 32 3d 3c 3f 3e 39 38 3b 3a
25 24 27 26 21 20 23 22 2d 2c 2f 2e 29 28 2b 2a
d5 d4 d7 d6 d1 d0 d3 d2 dd dc df de d9 d8 db da
c5 c4 c7 c6 c1 c0 c3 c2 cd cc cf ce c9 c8 cb ca
f5 f4 f7 f6 f1 f0 f3 f2 fd fc ff fe f9 f8 fb fa
e5 e4 e7 e6 e1 e0 e3 e2 ed ec ef ee e9 e8 eb ea
95 94 97 96 91 90 93 92 9d 9c 9f 9e 99 98 9b 9a
85 84 87 86 81 80 83 82 8d 8c 8f 8e 89 88 8b 8a
b5 b4 b7 b6 b1 b0 b3 b2 bd bc bf be b9 b8 bb ba
a5 a4 a7 a6 a1 a0 a3 a2 ad ac af ae a9 a8 50 cb
27 0c b7`

func TestMSTPCOBSAndCRC32KRFC8163(t *testing.T) {
	wire, err := hex.DecodeString(strings.Join(strings.Fields(mstpRFC8163), ""))
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"valid", "crc", "cobs", "pad"} {
		t.Run(variant, func(t *testing.T) {
			data := bytes.Clone(wire)
			switch variant {
			case "crc":
				data[len(data)-1] ^= 1
			case "cobs":
				data[8] = 0x55
			case "pad":
				data = append(data, 0xff)
			}
			p := gopacket.NewPacket(data, captureBusDecoder(165), gopacket.Default)
			if p.ErrorLayer() != nil {
				t.Fatal(p.ErrorLayer())
			}
			f := p.Layer(linkaudit.LayerLinkFrame).(*linkaudit.LinkFrame)
			if !bytes.Equal(p.Data(), data) || f.Fields["header_crc_valid"] != "true" {
				t.Fatal(f)
			}
			if variant == "cobs" {
				if f.Fields["cobs_valid"] != "false" || f.Decoded != nil {
					t.Fatal(f)
				}
				return
			}
			if f.Fields["cobs_valid"] != "true" || len(f.Decoded) != 533 {
				t.Fatal(f.Fields, len(f.Decoded))
			}
			if variant == "crc" {
				if f.Fields["data_crc32k_valid"] != "false" {
					t.Fatal(f.Fields)
				}
				return
			}
			expected, _ := hex.DecodeString("78d6003a3f000000000000000100018000783f2ee50002e4dbe8553ba00400")
			for i := 8; i < 510; i++ {
				expected = append(expected, byte(i))
			}
			if !bytes.Equal(f.Decoded, expected) || f.Fields["data_crc32k_valid"] != "true" || f.Fields["data_crc32k"] != "0xe259729e" {
				t.Fatal(f.Fields)
			}
		})
	}
}

func TestMSTPCOBSBlockBounds(t *testing.T) {
	for _, wire := range [][]byte{nil, {0x55}, {0x57}, {0x57, 0x55}} {
		if _, err := decodeMSTPCOBS(wire); err == nil {
			t.Fatal("invalid COBS accepted", wire)
		}
	}
	wire := append([]byte{255 ^ 0x55}, bytes.Repeat([]byte{1 ^ 0x55}, 254)...)
	wire = append(wire, 1^0x55)
	decoded, err := decodeMSTPCOBS(wire)
	if err != nil || !bytes.Equal(decoded, bytes.Repeat([]byte{1}, 254)) {
		t.Fatal(len(decoded), err)
	}
}

func TestMSTPDecodedAuditPayloadIsOptIn(t *testing.T) {
	wire, err := hex.DecodeString(strings.Join(strings.Fields(mstpRFC8163), ""))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"", "link-payload"} {
		out := runHuntInput(t, huntPCAP(165, wire), mode)
		records := bookRecords(t, out, "LinkFrame", func() *types.LinkFrame { return &types.LinkFrame{} })
		if len(records) != 1 || records[0].Fields["data_crc32k_valid"] != "true" || !bytes.Equal(records[0].Header, wire[:8]) {
			t.Fatal(records)
		}
		if mode == "link-payload" {
			if !bytes.Equal(records[0].Payload, wire[8:]) || len(records[0].DecodedPayload) != 533 {
				t.Fatal("payload evidence changed")
			}
		} else if len(records[0].Payload) != 0 || len(records[0].DecodedPayload) != 0 {
			t.Fatal("payload opt-in bypassed")
		}
	}
}
