package gateway

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"sync/atomic"
	"testing"
)

func readDNPFixture(c net.Conn) (dnpFrame, error) {
	var h [10]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return dnpFrame{}, err
	}
	if h[2] < 5 {
		return dnpFrame{}, errFrame
	}
	n := int(h[2]) - 5
	b := make([]byte, n+2*((n+15)/16))
	if _, err := io.ReadFull(c, b); err != nil {
		return dnpFrame{}, err
	}
	return parseDNPFrame(append(h[:], b...))
}
func dnpFixture(t *testing.T, fragmentResponse bool, confirmedResponse ...bool) (*wireOrigin, *atomic.Int32) {
	effects := new(atomic.Int32)
	o := fixtureOrigin(t, func(c net.Conn, o *wireOrigin) {
		var transport, application []byte
		expected := true
		reset := false
		var seq byte
		responseReset, responseFCB := false, true
		for {
			f, err := readDNPFixture(c)
			if err != nil {
				return
			}
			o.record(f.wire())
			if f.control == 0xc0 {
				reset = true
				expected = true
				c.Write((dnpFrame{source: f.destination, destination: f.source}).wire())
				continue
			}
			if f.control&15 == 3 {
				if !reset || f.control&0x20 != 0 != expected {
					return
				}
				expected = !expected
				c.Write((dnpFrame{source: f.destination, destination: f.source}).wire())
			}
			if len(f.data) == 0 {
				return
			}
			if f.data[0]&0x80 != 0 {
				transport = nil
			}
			transport = append(transport, f.data[1:]...)
			if f.data[0]&0x40 == 0 {
				continue
			}
			if len(transport) < 2 {
				return
			}
			control, function := transport[0], transport[1]
			if function == 0 {
				continue
			}
			if control&0x80 != 0 {
				application = nil
			}
			application = append(application, transport[2:]...)
			if control&0x20 != 0 {
				c.Write((dnpFrame{control: 0x44, source: f.destination, destination: f.source, data: []byte{0xc0 | seq, 0xc0 | control&15, 0}}).wire())
				seq = (seq + 1) & 63
			}
			if control&0x40 == 0 {
				continue
			}
			if function == 2 || function == 4 || function == 5 || function == 6 {
				effects.Add(1)
			}
			if function == 6 {
				continue
			}
			objects := []byte{1, 2, 0, 0, 0, 1}
			count := 1
			if fragmentResponse {
				count = 2
			}
			confirmed := len(confirmedResponse) > 0 && confirmedResponse[0]
			if confirmed && !responseReset {
				c.Write((dnpFrame{control: 0x40, source: f.destination, destination: f.source}).wire())
				ack, e := readDNPFixture(c)
				if e != nil || ack.control != 0x80 {
					return
				}
				responseReset = true
			}
			for i := 0; i < count; i++ {
				appControl := byte(0xc0) | (control+byte(i))&15
				part := objects
				if fragmentResponse {
					appControl = 0x20 | (control+byte(i))&15
					if i == 0 {
						appControl |= 0x80
					} else {
						appControl |= 0x40
						part = []byte{1, 2, 0, 1, 1, 1}
					}
				}
				response := dnpFrame{control: 0x44, source: f.destination, destination: f.source, data: append([]byte{0xc0 | seq, appControl, 129, 0, 0}, part...)}
				if confirmed {
					response.control = 0x53
					if responseFCB {
						response.control |= 0x20
					}
					responseFCB = !responseFCB
				}
				seq = (seq + 1) & 63
				c.Write(response.wire())
				if confirmed {
					ack, e := readDNPFixture(c)
					if e != nil || ack.control != 0x80 {
						return
					}
					o.record(ack.wire())
				}
				if fragmentResponse {
					ack, e := readDNPFixture(c)
					if e != nil || len(ack.data) != 3 || ack.data[2] != 0 || ack.data[1] != 0xc0|appControl&15 {
						return
					}
					o.record(ack.wire())
				}
			}
		}
	})
	return o, effects
}

func TestDNP3ConfirmedResponseLinkAndApplicationReceipt(t *testing.T) {
	o, _ := dnpFixture(t, true, true)
	c, _, _ := startTCPGateway(t, Config{Protocol: "dnp3", Upstream: o.listener.Addr().String()}, allowAll())
	c.Write(dnpRequest(0xc0, 1, []byte{60, 2, 6}).wire())
	for i := 0; i < 2; i++ {
		f, e := readDNPFixture(c)
		if e != nil || f.control != 0x44 || f.data[1]&0x20 != 0 {
			t.Fatalf("confirmed response termination: %+v %v", f, e)
		}
	}
	c.Close()
	o.wait(t)
}
func dnpRequest(appControl, function byte, objects []byte) dnpFrame {
	return dnpFrame{control: 0xc4, source: 4, destination: 3, data: append([]byte{0xc1, appControl, function}, objects...)}
}
func crob(index byte) []byte {
	return []byte{12, 1, 0x17, 1, index, 3, 1, 100, 0, 0, 0, 100, 0, 0, 0, 0}
}

func TestDNP3CapturedCRCAndObjectMetadata(t *testing.T) {
	captures := []string{
		"05641ac403000400c9b7c1c1030c0128010001000301640000007b5e6400000000005b",
		"05640bc403000400ef7ac1c1013c0206b576",
		"056412c403000400152dc1c10232010701fa7d0b460d01c863",
	}
	for _, s := range captures {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parseDNPFrame(b)
		if err != nil || !bytes.Equal(f.wire(), b) {
			t.Fatalf("captured frame CRC/blocks mismatch: %v", err)
		}
		metadata, err := dnpObjects(f.data[3:], f.data[2], 128)
		if err != nil || len(metadata) != 1 {
			t.Fatalf("capture metadata: %+v %v", metadata, err)
		}
		if metadata[0]["dnp3.range"] == "all" {
			if _, present := metadata[0]["dnp3.count"]; present {
				t.Fatal("all-objects range invented a point count")
			}
		}
	}
}
func TestDNP3TransportApplicationGateNoForbiddenEffects(t *testing.T) {
	o, effects := dnpFixture(t, true)
	p := compileGatewayPolicy(t, `Protocol == "dnp3" && Attributes["dnp3.object_group"] == "12" && Attributes["dnp3.address_end"] == "99"`)
	c, _, _ := startTCPGateway(t, Config{Protocol: "dnp3", Upstream: o.listener.Addr().String()}, p)
	// An allowed poll commits and its two application response fragments retain
	// their direction and CRCs, with CON terminated on the gateway's upstream leg.
	writeSplit(t, c, dnpRequest(0xc1, 1, []byte{60, 2, 6}).wire())
	for i := 0; i < 2; i++ {
		f, e := readDNPFixture(c)
		if e != nil || f.control != 0x44 || f.source != 3 || f.destination != 4 || f.data[1]&0x20 != 0 {
			t.Fatalf("response direction/confirmation: %+v %v", f, e)
		}
	}
	// Confirmed link requests are acknowledged locally, including a duplicate.
	reset := dnpFrame{control: 0xc0, source: 4, destination: 3}
	c.Write(reset.wire())
	if f, e := readDNPFixture(c); e != nil || f.control != 0 {
		t.Fatal("reset did not progress")
	}
	objects := append(crob(7), crob(99)...)
	// One application request spans four confirmed transport frames. Both
	// objects must be authorized before any of those frames reach the origin.
	var frames []dnpFrame
	app := append([]byte{0xe2, 4}, objects...)
	for i := 0; i < 4; i++ {
		start, end := i*len(app)/4, (i+1)*len(app)/4
		transport := byte(i)
		control := byte(0xf3)
		if i%2 == 1 {
			control = 0xd3
		}
		if i == 0 {
			transport |= 0x80
		}
		if i == 3 {
			transport |= 0x40
		}
		frames = append(frames, dnpFrame{control: control, source: 4, destination: 3, data: append([]byte{transport}, app[start:end]...)})
	}
	for i, f := range frames {
		writeSplit(t, c, f.wire())
		if ack, e := readDNPFixture(c); e != nil || ack.control != 0 {
			t.Fatalf("link ACK %d: %+v %v", i, ack, e)
		}
		if i == 0 {
			c.Write(f.wire())
			if ack, e := readDNPFixture(c); e != nil || ack.control != 0 {
				t.Fatal("duplicate not acknowledged")
			}
		}
		if i == len(frames)-1 {
			if confirm, e := readDNPFixture(c); e != nil || len(confirm.data) != 3 || confirm.data[2] != 0 {
				t.Fatalf("application confirm did not progress: %+v %v", confirm, e)
			}
		}
	}
	io.ReadAll(c)
	c.Close()
	o.wait(t)
	if effects.Load() != 0 || bytes.Contains(o.snapshot(), crob(99)) {
		t.Fatalf("forbidden CROB escaped hold: effects=%d bytes=%x", effects.Load(), o.snapshot())
	}
}
func TestDNP3ConfirmedAllowedWriteOriginSequence(t *testing.T) {
	o, effects := dnpFixture(t, false)
	c, _, _ := startTCPGateway(t, Config{Protocol: "dnp3", Upstream: o.listener.Addr().String()}, allowAll())
	c.Write((dnpFrame{control: 0xc0, source: 4, destination: 3}).wire())
	readDNPFixture(c)
	for i := 0; i < 2; i++ {
		f := dnpRequest(0xc0|byte(i), 4, crob(byte(i)))
		f.control = 0xf3
		if i%2 == 1 {
			f.control = 0xd3
		}
		c.Write(f.wire())
		if ack, e := readDNPFixture(c); e != nil || ack.control != 0 {
			t.Fatal("missing ACK")
		}
		if _, e := readDNPFixture(c); e != nil {
			t.Fatal(e)
		}
		if i == 0 {
			c.Write(f.wire())
			if ack, e := readDNPFixture(c); e != nil || ack.control != 0 {
				t.Fatal("completed request link retry not acknowledged")
			}
		}
	}
	c.Close()
	o.wait(t)
	if effects.Load() != 2 {
		t.Fatalf("allowed operations did not commit: %d", effects.Load())
	}
}

func TestDNP3ApplicationReplayClosesWithoutSecondEffect(t *testing.T) {
	o, effects := dnpFixture(t, false)
	c, _, _ := startTCPGateway(t, Config{Protocol: "dnp3", Upstream: o.listener.Addr().String()}, allowAll())
	f := dnpRequest(0xc0, 4, crob(7))
	c.Write(f.wire())
	if _, e := readDNPFixture(c); e != nil {
		t.Fatal(e)
	}
	c.Write(f.wire())
	io.ReadAll(c)
	c.Close()
	o.wait(t)
	if effects.Load() != 1 {
		t.Fatalf("application replay executed twice: %d", effects.Load())
	}
}
func TestDNP3MalformedAndUnsupportedNeverDial(t *testing.T) {
	valid := dnpRequest(0xc0, 4, crob(7)).wire()
	badHeader := append([]byte(nil), valid...)
	badHeader[8] ^= 1
	badBlock := append([]byte(nil), valid...)
	badBlock[len(badBlock)-1] ^= 1
	wrongTransport := dnpRequest(0xc0, 4, crob(7))
	wrongTransport.data[0] = 0x40
	unknown := dnpRequest(0xc0, 4, []byte{99, 1, 6}).wire()
	badSequence := dnpFrame{control: 0xd3, source: 4, destination: 3, data: []byte{0xc0, 0xc0, 1, 60, 2, 6}}.wire()
	object := crob(7)
	crossAPDU := append(dnpRequest(0x80, 4, object[:6]).wire(), dnpRequest(0x41, 4, object[6:]).wire()...)
	requestTrain := append(dnpRequest(0x80, 4, crob(7)).wire(), dnpRequest(0x41, 4, crob(99)).wire()...)
	for i, b := range [][]byte{badHeader, badBlock, wrongTransport.wire(), unknown, badSequence, crossAPDU, requestTrain} {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			o := fixtureOrigin(t, func(c net.Conn, o *wireOrigin) { o.record([]byte("connected")) })
			c, _, _ := startTCPGateway(t, Config{Protocol: "dnp3", Upstream: o.listener.Addr().String()}, allowAll())
			c.Write(b)
			io.ReadAll(c)
			o.listener.Close()
			o.wait(t)
			if len(o.snapshot()) != 0 {
				t.Fatal("malformed/unsupported request reached origin")
			}
		})
	}
}

func TestDNP3TransportSequenceWrapAndFragmentLimit(t *testing.T) {
	app := []byte{0xc0, 1}
	for i := 0; i < 31; i++ {
		app = append(app, 60, 2, 6)
	}
	makeFrames := func() [][]byte {
		var frames [][]byte
		for i, v := range app {
			control := byte(60+i) & 63
			if i == 0 {
				control |= 0x80
			}
			if i == len(app)-1 {
				control |= 0x40
			}
			frames = append(frames, (dnpFrame{control: 0xc4, source: 4, destination: 3, data: []byte{control, v}}).wire())
		}
		return frames
	}
	t.Run("wrap", func(t *testing.T) {
		o, _ := dnpFixture(t, false)
		c, _, _ := startTCPGateway(t, Config{Protocol: "dnp3", Upstream: o.listener.Addr().String()}, allowAll())
		c.Write(bytes.Join(makeFrames(), nil))
		if _, e := readDNPFixture(c); e != nil {
			t.Fatal(e)
		}
		c.Close()
		o.wait(t)
	})
	t.Run("bounded", func(t *testing.T) {
		o := fixtureOrigin(t, func(c net.Conn, o *wireOrigin) { o.record([]byte("connected")) })
		c, _, _ := startTCPGateway(t, Config{Protocol: "dnp3", Upstream: o.listener.Addr().String(), MaxStateEntries: 4}, allowAll())
		c.Write(bytes.Join(makeFrames(), nil))
		io.ReadAll(c)
		o.listener.Close()
		o.wait(t)
		if len(o.snapshot()) != 0 {
			t.Fatal("fragment limit reached origin")
		}
	})
}
func FuzzDNP3Bounded(f *testing.F) {
	f.Add(dnpRequest(0xc0, 4, crob(7)).wire())
	f.Add([]byte{5, 100, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 8192 {
			return
		}
		frame, err := parseDNPFrame(b)
		if err == nil {
			if len(frame.data) > 250 || !bytes.Equal(frame.wire(), b) {
				t.Fatal("invalid frame accepted")
			}
		}
		if len(b) > 0 {
			dnpObjects(b[1:], 1+b[0]%6, 128)
		}
	})
}
