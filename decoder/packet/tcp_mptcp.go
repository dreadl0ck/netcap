package packet

import (
	"bytes"

	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

// gopacket leaves OptionData empty for MPTCP, including unknown subtypes.
func tcpRawOptions(tcp *layers.TCP) [][]byte {
	if !tcp.Multipath {
		return nil
	}
	end := min(int(tcp.DataOffset)*4, len(tcp.Contents), 60)
	var options [][]byte
	for offset := 20; offset < end; {
		kind := tcp.Contents[offset]
		n := 1
		if kind > 1 {
			if offset+1 >= end {
				break
			}
			n = int(tcp.Contents[offset+1])
			if n < 2 || n > end-offset {
				break
			}
		}
		var raw []byte
		if kind == layers.TCPOptionKindMultipathTCP {
			raw = bytes.Clone(tcp.Contents[offset : offset+n])
		}
		options = append(options, raw)
		offset += n
		if kind == 0 {
			break
		}
	}
	return options
}

func tcpMPTCPOption(o layers.TCPOption, raw []byte) *types.TCPMPTCPOption {
	m := &types.TCPMPTCPOption{Subtype: uint32(o.OptionMultipath)}
	if len(raw) > 0 {
		m.Subtype = uint32(raw[0] >> 4)
	}
	if c := o.OptionMPTCPMpCapable; c != nil {
		var flags uint32
		for _, set := range []bool{c.A, c.B, c.C, c.D, c.E, c.F, c.G, c.H} {
			flags <<= 1
			if set {
				flags |= 1
			}
		}
		m.Capable = &types.MPTCPCapable{Version: uint32(c.Version), Flags: flags, SenderKey: bytes.Clone(c.SendKey), ReceiverKey: bytes.Clone(c.ReceivKey), DataLength: uint32(c.DataLength), Checksum: uint32(c.Checksum)}
	}
	if j := o.OptionMPTCPMpJoin; j != nil {
		m.Join = &types.MPTCPJoin{Backup: j.Backup, AddressID: uint32(j.AddrID), ReceiverToken: j.ReceivToken, SenderRandom: j.SendRandNum, SenderHMAC: bytes.Clone(j.SendHMAC)}
	}
	if d := o.OptionMPTCPDss; d != nil {
		m.DSS = &types.MPTCPDSS{DataFIN: d.F, ACKPresent: d.A, MappingPresent: d.M, DataACK: bytes.Clone(d.DataAck), DSN: bytes.Clone(d.DSN), SubflowSequence: d.SSN, DataLength: uint32(d.DataLength), Checksum: uint32(d.Checksum)}
		// The upstream a/m flags are unexported; retain their exact wire values.
		if len(raw) >= 2 {
			m.DSS.ACK64 = raw[1]&2 != 0
			m.DSS.DSN64 = raw[1]&8 != 0
		}
		if d.M {
			m.DSS.ChecksumPresent = int(o.OptionLength) == 4+len(d.DataAck)+len(d.DSN)+8
		}
	}
	if a := o.OptionMPTCPAddAddr; a != nil {
		m.AddAddr = &types.MPTCPAddAddr{IPVersion: uint32(a.IPVer), Echo: a.E, AddressID: uint32(a.AddrID), Address: a.Address.String(), Port: uint32(a.Port), SenderHMAC: bytes.Clone(a.SendHMAC)}
		// Upstream's HMAC slice extends into subsequent options; bound it here.
		if len(m.AddAddr.SenderHMAC) > 8 {
			m.AddAddr.SenderHMAC = m.AddAddr.SenderHMAC[:8]
		}
	}
	if r := o.OptionMTCPRemAddr; r != nil {
		m.RemoveAddr = &types.MPTCPRemoveAddr{}
		for _, id := range r.AddrIDs {
			m.RemoveAddr.AddressIDs = append(m.RemoveAddr.AddressIDs, uint32(id))
		}
	}
	if p := o.OptionMPTCPMpPrio; p != nil {
		m.Priority = &types.MPTCPPriority{Backup: p.Backup, AddressID: uint32(p.AddrID), AddressIDPresent: o.OptionLength == 4}
	}
	if f := o.OptionMTCPMPFail; f != nil {
		m.Fail = &types.MPTCPFail{DSN: f.DSN}
	}
	if f := o.OptionMTCPMPFastClose; f != nil {
		m.FastClose = &types.MPTCPFastClose{ReceiverKey: bytes.Clone(f.ReceivKey)}
	}
	if r := o.OptionMPTCPMPTcpRst; r != nil {
		m.TCPReset = &types.MPTCPReset{U: r.U, V: r.V, W: r.W, Transient: r.T, Reason: uint32(r.Reason)}
	}
	return m
}
