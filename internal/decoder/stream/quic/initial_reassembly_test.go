package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"testing"
)

type initialWriter struct {
	netio.AuditRecordWriter
	records []*types.QUICClientHello
}

func (w *initialWriter) Write(m proto.Message) error {
	w.records = append(w.records, proto.Clone(m).(*types.QUICClientHello))
	return nil
}

func initialPacket(t *testing.T, version uint32, dcid []byte, pn byte, offset byte, fragment []byte) []byte {
	t.Helper()
	first := byte(0xc0)
	keyLabel, ivLabel, hpLabel := "quic key", "quic iv", "quic hp"
	if version == quicVersionIETF2 {
		first = 0xd0
		keyLabel, ivLabel, hpLabel = "quicv2 key", "quicv2 iv", "quicv2 hp"
	}
	secret := hkdfExpandLabel(hkdfExtract(getSaltForVersion(version), dcid), []byte("client in"), nil, 32)
	key := hkdfExpandLabel(secret, []byte(keyLabel), nil, 16)
	iv := hkdfExpandLabel(secret, []byte(ivLabel), nil, 12)
	hp := hkdfExpandLabel(secret, []byte(hpLabel), nil, 16)
	plain := append([]byte{2, 0, 0, 0, 0, 6, offset, byte(len(fragment))}, fragment...)
	plain = append(plain, make([]byte, 32)...)
	header := binary.BigEndian.AppendUint32([]byte{first}, version)
	header = append(header, byte(len(dcid)))
	header = append(header, dcid...)
	header = append(header, 0, 0)
	length := 1 + len(plain) + 16
	header = binary.BigEndian.AppendUint16(header, uint16(length)|0x4000)
	pnOffset := len(header)
	header = append(header, pn)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	iv[11] ^= pn
	wire := append(header, gcm.Seal(nil, iv, plain, header)...)
	mask := make([]byte, 16)
	block, err = aes.NewCipher(hp)
	if err != nil {
		t.Fatal(err)
	}
	block.Encrypt(mask, wire[pnOffset+4:pnOffset+20])
	wire[0] ^= mask[0] & 15
	wire[pnOffset] ^= mask[1]
	return wire
}

func TestQUICInitialCryptoAcrossPacketsAndVersions(t *testing.T) {
	old, count := Decoder.Writer, Decoder.NumRecordsWritten
	t.Cleanup(func() { Decoder.Writer, Decoder.NumRecordsWritten = old, count })
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 1, 1, 0, 0, 0)
	hello := append([]byte{1, 0, 0, byte(len(body))}, body...)
	for _, version := range []uint32{quicVersionIETF1, quicVersionIETF2} {
		for split := 1; split < len(hello); split++ {
			w := &initialWriter{}
			Decoder.Writer = w
			q := &quicReader{conversation: &core.ConversationInfo{ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", CommunityID: "id"}}
			dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
			first := initialPacket(t, version, dcid, 0, 0, hello[:split])
			last := initialPacket(t, version, dcid, 1, byte(split), hello[split:])
			// Reordered CRYPTO offsets, an ACK before CRYPTO, coalesced packets and a retransmission.
			q.parseIETFQUIC(append(append(append([]byte(nil), last...), first...), first...), 123)
			if len(w.records) != 1 || len(w.records[0].CipherSuites) != 1 || w.records[0].Timestamp != 123 || w.records[0].CommunityID != "id" {
				t.Fatalf("version %x split %d: %v", version, split, w.records)
			}
		}
	}
}

func TestQUICCryptoDoesNotInventMissingBytes(t *testing.T) {
	if b := reassembleCryptoFragments([]cryptoFragment{{offset: 4, data: []byte{1, 2, 3}}}); len(b) != 0 {
		t.Fatal("hole filled with zeroes", b)
	}
	if b := reassembleCryptoFragments([]cryptoFragment{{data: []byte{1, 2}}, {offset: 1, data: []byte{3}}}); b != nil {
		t.Fatal("conflicting overlap accepted", b)
	}
	if b := reassembleCryptoFragments([]cryptoFragment{{offset: ^uint64(0), data: []byte{1, 2}}}); b != nil {
		t.Fatal("offset overflow accepted")
	}
}
