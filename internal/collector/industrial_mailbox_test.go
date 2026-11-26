package collector

import (
	"testing"

	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

func TestIndustrialMailboxLifecycle(t *testing.T) {
	coe := func(s *layers.EtherCATSDO) *layers.EtherCATMailbox {
		return &layers.EtherCATMailbox{Type: layers.EtherCATMailboxCoE, CoE: &layers.EtherCATCoE{Service: layers.EtherCATCoESDOResponse, SDO: s}}
	}
	eoe := func(seq uint8, off uint16, last bool) *layers.EtherCATMailbox {
		return &layers.EtherCATMailbox{Type: layers.EtherCATMailboxEoE, EoE: &layers.EtherCATEoE{FrameNo: 2, FragmentNo: seq, Offset: off, LastFragment: last, Data: make([]byte, 32)}}
	}
	foe := func(op layers.EtherCATFoEOpCode, n uint32, data string) *layers.EtherCATMailbox {
		return &layers.EtherCATMailbox{Type: layers.EtherCATMailboxFoE, FoE: &layers.EtherCATFoE{OpCode: op, PacketNo: n, Data: []byte(data)}}
	}
	soe := func(drive uint8, more bool) *layers.EtherCATMailbox {
		return &layers.EtherCATMailbox{Type: layers.EtherCATMailboxSoE, SoE: &layers.EtherCATSoE{OpCode: layers.EtherCATSoEReadResponse, DriveNo: drive, Incomplete: more, FragmentsLeft: 1, Data: []byte("xy")}}
	}
	ctx := &types.PacketContext{NetworkScope: "vlan:11", SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02"}
	for _, tc := range []struct {
		name string
		mail []*layers.EtherCATMailbox
		kind layers.EtherCATTransferKind
		size uint32
	}{
		{"CoE", []*layers.EtherCATMailbox{coe(&layers.EtherCATSDO{Specifier: layers.EtherCATSDOSCSInitiateUpload, Index: 0x1008, Value: 6, Data: []byte("dev")}), coe(&layers.EtherCATSDO{Segment: true, LastSegment: true, Data: []byte("ice")})}, layers.EtherCATTransferSDOUpload, 6},
		{"EoE", []*layers.EtherCATMailbox{eoe(0, 0, false), eoe(1, 32, true)}, layers.EtherCATTransferEoE, 64},
		{"FoE", []*layers.EtherCATMailbox{foe(layers.EtherCATFoERRQ, 0, "sample"), foe(layers.EtherCATFoEDATA, 1, "abcd"), foe(layers.EtherCATFoEDATA, 2, "e")}, layers.EtherCATTransferFoE, 5},
		{"SoE", []*layers.EtherCATMailbox{soe(1, true), soe(1, false)}, layers.EtherCATTransferSoE, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := industrialCapture{ec: make(map[string]*ecTransfer)}
			feed := func(m *layers.EtherCATMailbox, at int64) *types.MailboxTransfer {
				d := layers.EtherCATDatagram{Command: layers.EtherCATCommandFPRD, Address: 0x1001, Mailbox: m}
				return o.ethercat(&layers.EtherCAT{Datagrams: []layers.EtherCATDatagram{d}}, ctx, at).Mailboxes[0]
			}
			for i, m := range tc.mail {
				r := feed(m, int64(10+i))
				if r.FirstTimestamp != 10 || r.Station != 0x1001 {
					t.Fatal(r)
				}
				if i+1 < len(tc.mail) {
					if r.Status != "pending" {
						t.Fatal(r)
					}
				} else if r.Status != "complete" || r.Kind != tc.kind.String() || r.Length != tc.size || len(o.ec) != 0 {
					t.Fatal(r)
				}
			}
			for _, end := range []struct {
				all bool
				why string
			}{{false, "idle expiry"}, {true, "EOF"}} {
				feed(tc.mail[0], 20)
				if tc.name == "FoE" {
					feed(tc.mail[1], 21)
				}
				if tc.name == "SoE" {
					feed(soe(2, true), 22)
					if r := feed(soe(2, false), 23); r.Status != "complete" || r.FirstTimestamp != 22 {
						t.Fatal(r)
					}
				}
				if rows := o.expire(20, false); len(rows) != 0 {
					t.Fatal("premature expiry", rows)
				}
				rows := o.expire(25, end.all)
				if len(rows) != 1 || len(o.ec) != 0 || rows[0].scope != ctx.NetworkScope || rows[0].record.Time() != 20 {
					t.Fatal(rows)
				}
				r := rows[0].record.(*types.EtherCAT).Mailboxes[0]
				if r.Status != "incomplete: "+end.why || r.FirstTimestamp != 20 || tc.name == "FoE" && r.Length != 4 {
					t.Fatal(r)
				}
			}
		})
	}
}
