/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package packet

import (
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

var ospfv3Decoder = newGoPacketDecoder(
	types.Type_NC_OSPFv3,
	layers.LayerTypeOSPF,
	"Open Shortest Path First (OSPF) v3 is a routing protocol for Internet Protocol (IP) networks with support for IPv6",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if ospf3, ok := layer.(*layers.OSPFv3); ok {
			var (
				hello  *types.HelloPkg
				dbDesc *types.DbDescPkg
				lSR    []*types.LSReq
				lSU    *types.LSUpdate
				lSAs   []*types.LSAheader
			)
			switch v := ospf3.Content.(type) {
			case layers.HelloPkg:
				hello = &types.HelloPkg{
					InterfaceID:              v.InterfaceID,
					RtrPriority:              int32(v.RtrPriority),
					Options:                  v.Options,
					HelloInterval:            int32(v.HelloInterval),
					RouterDeadInterval:       v.RouterDeadInterval,
					DesignatedRouterID:       v.DesignatedRouterID,
					BackupDesignatedRouterID: v.BackupDesignatedRouterID,
					NeighborID:               v.NeighborID,
				}
			case layers.DbDescPkg:
				var lsas []*types.LSAheader
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
				dbDesc = &types.DbDescPkg{
					Options:      v.Options,
					InterfaceMTU: int32(v.InterfaceMTU),
					Flags:        int32(v.Flags),
					DDSeqNumber:  v.DDSeqNumber,
					LSAinfo:      lsas, // []*LSAheader
				}
			case []layers.LSReq:
				for _, r := range v {
					lSR = append(lSR, &types.LSReq{
						LSType:    int32(r.LSType),
						LSID:      r.LSID,
						AdvRouter: r.AdvRouter,
					})
				}
			case layers.LSUpdate:
				lSU = decoderLSUpdate(v)
			case []layers.LSAheader:
				for _, r := range v {
					lSAs = append(lSAs, &types.LSAheader{
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
			}

			return &types.OSPFv3{
				Timestamp:    timestamp,
				Version:      int32(ospf3.Version),
				Type:         int32(ospf3.Type),
				PacketLength: int32(ospf3.PacketLength),
				RouterID:     ospf3.RouterID,
				AreaID:       ospf3.AreaID,
				Checksum:     int32(ospf3.Checksum),
				Instance:     int32(ospf3.Instance),
				Reserved:     int32(ospf3.Reserved),
				Hello:        hello,  // *HelloPkg
				DbDesc:       dbDesc, // *DbDescPkg
				LSR:          lSR,    // []*LSReq
				LSU:          lSU,    // *LSUpdate
				LSAs:         lSAs,   // []*LSAheader
			}
		}

		return nil
	},
)

func decoderLSUpdate(v layers.LSUpdate) *types.LSUpdate {
	lsas := make([]*types.LSA, len(v.LSAs))

	for i, l := range v.LSAs {
		var (
			rLSAV2             *types.RouterLSAV2
			asExternalLSAV2    *types.ASExternalLSAV2
			routerLSA          *types.RouterLSA
			networkLSA         *types.NetworkLSA
			interAreaPrefixLSA *types.InterAreaPrefixLSA
			interAreaRouterLSA *types.InterAreaRouterLSA
			asExternalLSA      *types.ASExternalLSA
			linkLSA            *types.LinkLSA
			intraAreaPrefixLSA *types.IntraAreaPrefixLSA
		)

		switch val := l.Content.(type) {
		case layers.RouterLSAV2:
			var routers []*types.RouterV2
			for _, r := range val.Routers {
				routers = append(routers, &types.RouterV2{
					Type:     int32(r.Type),
					LinkID:   r.LinkID,
					LinkData: r.LinkData,
					Metric:   uint32(r.Metric),
				})
			}

			rLSAV2 = &types.RouterLSAV2{
				Flags:   int32(val.Flags),
				Links:   int32(val.Links),
				Routers: routers, // []*RouterV2,
			}
		case layers.ASExternalLSAV2:
			asExternalLSAV2 = &types.ASExternalLSAV2{
				NetworkMask:       val.NetworkMask,
				ExternalBit:       int32(val.ExternalBit),
				Metric:            val.Metric,
				ForwardingAddress: val.ForwardingAddress,
				ExternalRouteTag:  val.ExternalRouteTag,
			}
		case layers.RouterLSA:
			var routers []*types.Router
			for _, r := range val.Routers {
				routers = append(routers, &types.Router{
					Type:                int32(r.Type),
					Metric:              int32(r.Metric),
					InterfaceID:         r.InterfaceID,
					NeighborInterfaceID: r.NeighborInterfaceID,
					NeighborRouterID:    r.NeighborRouterID,
				})
			}

			routerLSA = &types.RouterLSA{
				Flags:   int32(val.Flags),
				Options: val.Options,
				Routers: routers, // []*Router
			}
		case layers.NetworkLSA:
			networkLSA = &types.NetworkLSA{
				Options:        val.Options,
				AttachedRouter: val.AttachedRouter,
			}
		case layers.InterAreaPrefixLSA:
			interAreaPrefixLSA = &types.InterAreaPrefixLSA{
				Metric:        val.Metric,
				PrefixLength:  int32(val.PrefixLength),
				PrefixOptions: int32(val.PrefixOptions),
				AddressPrefix: val.AddressPrefix,
			}
		case layers.InterAreaRouterLSA:
			interAreaRouterLSA = &types.InterAreaRouterLSA{
				Options:             val.Options,
				Metric:              val.Metric,
				DestinationRouterID: val.DestinationRouterID,
			}
		case layers.ASExternalLSA:
			asExternalLSA = &types.ASExternalLSA{
				Flags:             int32(val.Flags),
				Metric:            val.Metric,
				PrefixLength:      int32(val.PrefixLength),
				PrefixOptions:     int32(val.PrefixOptions),
				RefLSType:         int32(val.RefLSType),
				AddressPrefix:     val.AddressPrefix,
				ForwardingAddress: val.ForwardingAddress,
				ExternalRouteTag:  val.ExternalRouteTag,
				RefLinkStateID:    val.RefLinkStateID,
			}
		case layers.LinkLSA:
			var prefixes []*types.LSAPrefix
			for _, r := range val.Prefixes {
				prefixes = append(prefixes, &types.LSAPrefix{
					PrefixLength:  int32(r.PrefixLength),
					PrefixOptions: int32(r.PrefixOptions),
					Metric:        int32(r.Metric),
					AddressPrefix: r.AddressPrefix,
				})
			}

			linkLSA = &types.LinkLSA{
				RtrPriority:      int32(val.RtrPriority),
				Options:          val.Options,
				LinkLocalAddress: val.LinkLocalAddress,
				NumOfPrefixes:    val.NumOfPrefixes,
				Prefixes:         prefixes, // []*LSAPrefix
			}
		case layers.IntraAreaPrefixLSA:
			var prefixes []*types.LSAPrefix
			for _, r := range val.Prefixes {
				prefixes = append(prefixes, &types.LSAPrefix{
					PrefixLength:  int32(r.PrefixLength),
					PrefixOptions: int32(r.PrefixOptions),
					Metric:        int32(r.Metric),
					AddressPrefix: r.AddressPrefix,
				})
			}
			intraAreaPrefixLSA = &types.IntraAreaPrefixLSA{
				NumOfPrefixes:  int32(val.NumOfPrefixes),
				RefLSType:      int32(val.RefLSType),
				RefLinkStateID: val.RefLinkStateID,
				RefAdvRouter:   val.RefAdvRouter,
				Prefixes:       prefixes,
			}
		}
		lsas[i] = &types.LSA{
			Header: &types.LSAheader{
				LSAge:       int32(l.LSAge),
				LSType:      int32(l.LSType),
				LinkStateID: l.LinkStateID,
				AdvRouter:   l.AdvRouter,
				LSSeqNumber: l.LSSeqNumber,
				LSChecksum:  int32(l.LSChecksum),
				Length:      int32(l.Length),
				LSOptions:   int32(l.LSOptions),
			},
			RLSAV2:          rLSAV2,
			ASELSAV2:        asExternalLSAV2,
			RLSA:            routerLSA,
			NLSA:            networkLSA,
			InterAPrefixLSA: interAreaPrefixLSA,
			IARouterLSA:     interAreaRouterLSA,
			ASELSA:          asExternalLSA,
			LLSA:            linkLSA,
			IntraAPrefixLSA: intraAreaPrefixLSA,
		}
	}

	return &types.LSUpdate{
		NumOfLSAs: v.NumOfLSAs,
		LSAs:      lsas, // []*LSA
	}
}
