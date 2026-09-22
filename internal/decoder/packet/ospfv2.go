/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package packet

import (
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

var ospfv2Decoder = newGoPacketDecoder(
	types.Type_NC_OSPFv2,
	layers.LayerTypeOSPF,
	"Open Shortest Path First (OSPF) is a routing protocol for Internet Protocol (IP) networks",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if ospf2, ok := layer.(*layers.OSPFv2); ok {
			var (
				headers []*types.LSAheader
				update  *types.LSUpdate
				lreqs   []*types.LSReq
				dbdesc  *types.DbDescPkg
				hello   *types.HelloPkgV2
			)
			switch v := ospf2.Content.(type) {
			case []layers.LSAheader:
				for _, r := range v {
					headers = append(headers, &types.LSAheader{
						LSAge:       int32(r.LSAge),
						LSType:      int32(r.LSType),
						LinkStateID: r.LinkStateID,
						AdvRouter:   r.AdvRouter,
						LSSeqNumber: r.LSSeqNumber,
						LSChecksum:  int32(r.LSChecksum),
						Length:      int32(r.Length),
						LSOptions:   int32(r.LSOptions),
					})
				}
			case layers.LSUpdate:
				update = decoderLSUpdate(v)
			case []layers.LSReq:
				for _, r := range v {
					lreqs = append(lreqs, &types.LSReq{
						LSType:    int32(r.LSType),
						LSID:      r.LSID,
						AdvRouter: r.AdvRouter,
					})
				}
			case layers.DbDescPkg:
				lsas := make([]*types.LSAheader, 0, len(v.LSAinfo))
				for _, h := range v.LSAinfo {
					lsas = append(lsas, &types.LSAheader{
						LSAge:       int32(h.LSAge),
						LSType:      int32(h.LSType),
						LinkStateID: h.LinkStateID,
						AdvRouter:   h.AdvRouter,
						LSSeqNumber: h.LSSeqNumber,
						LSChecksum:  int32(h.LSChecksum),
						Length:      int32(h.Length),
						LSOptions:   int32(h.LSOptions),
					})
				}
				dbdesc = &types.DbDescPkg{
					Options:      v.Options,
					InterfaceMTU: int32(v.InterfaceMTU),
					Flags:        int32(v.Flags),
					DDSeqNumber:  v.DDSeqNumber,
					LSAinfo:      lsas, // []*LSAheader
				}
			case layers.HelloPkgV2:
				hello = &types.HelloPkgV2{
					InterfaceID:              v.InterfaceID,
					RtrPriority:              int32(v.RtrPriority),
					Options:                  v.Options,
					HelloInterval:            int32(v.HelloInterval),
					RouterDeadInterval:       v.RouterDeadInterval,
					DesignatedRouterID:       v.DesignatedRouterID,
					BackupDesignatedRouterID: v.BackupDesignatedRouterID,
					NeighborID:               v.NeighborID,
					NetworkMask:              v.NetworkMask,
				}
			}

			return &types.OSPFv2{
				Timestamp:      timestamp,
				Version:        int32(ospf2.Version),
				Type:           int32(ospf2.Type),
				PacketLength:   int32(ospf2.PacketLength),
				RouterID:       ospf2.RouterID,
				AreaID:         ospf2.AreaID,
				Checksum:       int32(ospf2.Checksum),
				AuType:         int32(ospf2.AuType),
				Authentication: int64(ospf2.Authentication),
				LSAs:           headers, // []*LSAheader
				LSU:            update,  // *LSUpdate
				LSR:            lreqs,   // []*LSReq
				DbDesc:         dbdesc,  // *DbDescPkg
				HelloV2:        hello,   // *HelloPkgV2
			}
		}

		return nil
	},
)
