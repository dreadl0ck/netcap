package stream

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/dns"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/profinet"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/rdp"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/s7comm"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/smb"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func round2AXFR(t *testing.T) ([]byte, []byte) {
	t.Helper()
	message := &layers.DNS{ID: 7, QR: true, QDCount: 1, ANCount: 1,
		Questions: []layers.DNSQuestion{{Name: []byte("example.test"), Type: layers.DNSType(252), Class: layers.DNSClassIN}},
		Answers: []layers.DNSResourceRecord{{Name: []byte("example.test"), Type: layers.DNSTypeTXT, Class: layers.DNSClassIN,
			TXTs: [][]byte{[]byte(strings.Repeat("a", 250)), []byte(strings.Repeat("b", 250)), []byte(strings.Repeat("c", 250)), []byte(strings.Repeat("d", 250))}}}}
	encode := func() []byte {
		buf := gopacket.NewSerializeBuffer()
		if err := message.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true}); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(len(buf.Bytes())))
		return append(b, buf.Bytes()...)
	}
	response := encode()
	message.QR, message.Answers = false, nil
	return encode(), response
}

func TestRound2SelectionCollisions(t *testing.T) {
	matchingEnv(t)
	query, answer := round2AXFR(t)
	mms := hexBytes("0300001611e00000b00100c0010ac1020001c2020002") // Zeek mmsX frames 4+5
	rdp := tpktFrame(append([]byte{0x0e, 0xe0, 0, 0, 0, 0, 0}, []byte{1, 0, 8, 0, 3, 0, 0, 0}...))
	for _, tc := range []struct {
		name, want     string
		port           int32
		client, server []byte
	}{
		{"HTTP upload containing framed SMB", "HTTP", 1551, append([]byte("POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 68\r\n\r\n"), smbNegotiate(false)...), nil},
		{"AXFR split prefix", "DNS", 53, query, answer},
		{"AXFR nonstandard port", "DNS", 5300, query, answer},
		{"RTMP random COTP-shaped handshake", "", 1935, append(hexBytes("0300aabbff700000"), make([]byte, 1529)...), nil},
		{"MMS COTP request", "", 102, mms, nil},
		{"non-Modbus COTP on 502", "", 502, mms, nil},
		{"unidentified COTP on RDP port", "", 3389, mms, nil},
		{"S7 after COTP on RDP port", "S7Comm", 3389, append(append([]byte(nil), mms...), s7JobPDU([]byte{0x04, 0})...), nil},
		{"RDP on S7 port", "RDP", 102, rdp, nil},
		{"RDP on alternate port", "RDP", 3390, rdp, nil},
		{"malformed RDP confirm is not S7", "", 3389, nil, hexBytes("030000130ed000001234000203000001000002001232000200080000000000")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, split := range []int{1, 2, 4, 7, len(tc.client)} {
				sel, ok := SelectDecoder(&SelectionInput{Transport: core.TCP, ServerPort: tc.port,
					PortClient: tc.client[:min(split, len(tc.client))], PortServer: tc.server[:min(2, len(tc.server))],
					ScanClient: tc.client, ScanServer: tc.server, Conversation: &core.ConversationInfo{}})
				if ok != (tc.want != "") || sel.Name != tc.want {
					t.Errorf("initial prefix %d: selected %q via %s, want %q", split, sel.Name, sel.Via, tc.want)
				}
			}
		})
	}
}

func TestRound2PartialInitialPackets(t *testing.T) {
	matchingEnv(t)
	for _, name := range []string{"SMB", "DNS", "S7Comm", "RDP", "PROFINET"} {
		s := matchingSample(t, name)
		for split := 0; split < len(s.client); split++ {
			t.Run(fmt.Sprintf("%s/%d", name, split), func(t *testing.T) {
				sel, ok := SelectDecoder(&SelectionInput{Transport: core.TCP, ServerPort: 64999,
					PortClient: s.client[:split], ScanClient: s.client, ScanServer: s.server,
					Conversation: &core.ConversationInfo{}})
				if !ok || sel.Name != name {
					t.Fatalf("selected %q, want %s", sel.Name, name)
				}
			})
		}
	}
}

func TestRound2FrameBoundaries(t *testing.T) {
	matchingEnv(t)
	for _, name := range []string{"SMB", "RDP", "S7Comm", "PROFINET"} {
		s := matchingSample(t, name)
		for _, prefix := range []string{"GET / HTTP/1.1\r\n\r\n", "garbage"} {
			if DefaultStreamDecoders[s.port].CanDecodeStream(append([]byte(prefix), s.client...), nil) {
				t.Errorf("%s accepted an embedded frame", name)
			}
		}
	}
	for _, name := range []string{"SMB", "RDP", "S7Comm"} {
		s := matchingSample(t, name)
		data := append([]byte(nil), s.client...)
		data[2], data[3] = 0, 7
		if DefaultStreamDecoders[s.port].CanDecodeStream(data, nil) {
			t.Errorf("%s read beyond its declared frame", name)
		}
	}
	data := pnioRequest()
	data[39] ^= 1
	if profinet.Decoder.CanDecodeStream(data, nil) {
		t.Fatal("UUID prefix alone identified PNIO")
	}
	// Connection-oriented bind, two transfer syntaxes, LE UUID at context offset.
	bind := make([]byte, 92)
	copy(bind, hexBytes("05000b03100000005c00000001000000b810b810000000000100000000000200"))
	copy(bind[32:48], hexBytes("0100a0de976cd111827100a02442df7d"))
	if !profinet.Decoder.CanDecodeStream(bind, nil) {
		t.Fatal("PNIO bind rejected")
	}
	bind[30] = 3
	if profinet.Decoder.CanDecodeStream(bind, nil) {
		t.Fatal("out-of-frame context accepted")
	}
	// A header plus a partial initial application body remains identifiable.
	if !smb.Decoder.CanDecodeStream(smbNegotiate(false)[:24], nil) {
		t.Fatal("partial SMB2 rejected")
	}
	if !s7comm.Decoder.CanDecodeStream(s7JobPDU([]byte{4, 0})[:17], nil) {
		t.Fatal("partial S7 rejected")
	}
	if !rdp.Decoder.CanDecodeStream(nil, hexBytes("030000130ed000001234000200080001000000")) {
		t.Fatal("server-only RDP negotiation rejected")
	}
	correlated := append(hexBytes("0300003732e00000000000010808000300000006002400"), make([]byte, 32)...)
	if !rdp.Decoder.CanDecodeStream(correlated, nil) {
		t.Fatal("RDP correlation info rejected")
	}
	correlated[21] = 35
	if rdp.Decoder.CanDecodeStream(correlated, nil) {
		t.Fatal("malformed RDP correlation length accepted")
	}
}

func TestRound2DNSMalformedControls(t *testing.T) {
	query, _ := round2AXFR(t)
	for _, tc := range []struct {
		name string
		edit func([]byte) []byte
	}{
		{"truncated body", func(b []byte) []byte { return b[:len(b)-1] }},
		{"undersized header", func(b []byte) []byte { binary.BigEndian.PutUint16(b, 11); return b }},
		{"reserved flag", func(b []byte) []byte { b[5] |= 0x40; return b }},
		{"reserved opcode", func(b []byte) []byte { b[4] = 3 << 3; return b }},
		{"compression pointer loop", func(b []byte) []byte { b[14], b[15] = 0xc0, 12; return b }},
		{"unframed DNS", func(b []byte) []byte { return b[2:] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if dns.Decoder.CanDecodeStream(tc.edit(append([]byte(nil), query...)), nil) {
				t.Fatal("malformed DNS identified")
			}
		})
	}
}

func TestRound2SMBSessionAndHeaderControls(t *testing.T) {
	frame := smbNegotiate(false)
	request := make([]byte, 72)
	copy(request, []byte{0x81, 0, 0, 68, 32})
	request[38] = 32
	for _, span := range [][2]int{{5, 37}, {39, 71}} {
		for i := span[0]; i < span[1]; i++ {
			request[i] = 'A'
		}
	}
	for _, setup := range [][]byte{request, {0x82, 0, 0, 0}, {0x85, 0, 0, 0}} {
		if !smb.Decoder.CanDecodeStream(append(append([]byte(nil), setup...), frame...), nil) {
			t.Fatal("SMB after NetBIOS setup rejected")
		}
		if smb.Decoder.CanDecodeStream(setup, nil) {
			t.Fatal("NetBIOS alone identified SMB")
		}
	}
	request[5] = 'Q'
	if smb.Decoder.CanDecodeStream(append(request, frame...), nil) {
		t.Fatal("invalid encoded NetBIOS name accepted")
	}
	for _, offset := range []int{8, 16} { // SMB2 structure size and command.
		bad := append([]byte(nil), frame...)
		bad[offset] = 0xff
		if smb.Decoder.CanDecodeStream(bad, nil) {
			t.Fatalf("invalid SMB2 header at %d accepted", offset)
		}
	}
	if smb.Decoder.CanDecodeStream(frame[4:], nil) {
		t.Fatal("unframed SMB signature accepted")
	}
}

func TestRound2PNIOByteOrder(t *testing.T) {
	data := pnioRequest()
	data[4] = 0
	copy(data[24:40], hexBytes("dea000016c9711d1827100a02442df7d"))
	binary.BigEndian.PutUint32(data[60:64], 1)
	if !profinet.Decoder.CanDecodeStream(data, nil) {
		t.Fatal("big-endian PNIO interface rejected")
	}
	data[4] = 0x10
	if profinet.Decoder.CanDecodeStream(data, nil) {
		t.Fatal("PNIO UUID parsed with wrong byte order")
	}
	if profinet.Decoder.CanDecodeStream(pnioRequest()[:79], nil) {
		t.Fatal("incomplete connectionless RPC header accepted")
	}
}

func FuzzRound2StructuralProbes(f *testing.F) {
	for _, name := range []string{"SMB", "DNS", "S7Comm", "RDP", "PROFINET"} {
		for _, s := range samples() {
			if s.decoder == name {
				f.Add(s.client)
			}
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			t.Skip()
		}
		for _, port := range []int32{445, 53, 102, 3389, 34964} {
			d := DefaultStreamDecoders[port]
			_ = d.CanDecodeStream(data, nil)
			if d.CanDecodeStream(append([]byte("POST / HTTP/1.1\r\n\r\n"), data...), nil) {
				t.Fatalf("%s matched HTTP body", d.GetName())
			}
		}
	})
}
