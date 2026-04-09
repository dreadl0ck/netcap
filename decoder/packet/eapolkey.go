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

var eapolkeyDecoder = newGoPacketDecoder(
	types.Type_NC_EAPOLKey,
	layers.LayerTypeEAPOLKey,
	"Extensible Authentication Protocol is an authentication framework frequently used in network and internet connections",
	func(layer gopacket.Layer, timestamp int64) proto.Message {
		if eapolkey, ok := layer.(*layers.EAPOLKey); ok {
			return &types.EAPOLKey{
				Timestamp:            timestamp,
				KeyDescriptorType:    int32(eapolkey.KeyDescriptorType),
				KeyDescriptorVersion: int32(eapolkey.KeyDescriptorVersion),
				KeyType:              int32(eapolkey.KeyType),
				KeyIndex:             int32(eapolkey.KeyIndex),
				Install:              eapolkey.Install,
				KeyACK:               eapolkey.KeyACK,
				KeyMIC:               eapolkey.KeyMIC,
				Secure:               eapolkey.Secure,
				MICError:             eapolkey.MICError,
				Request:              eapolkey.Request,
				HasEncryptedKeyData:  eapolkey.HasEncryptedKeyData,
				SMKMessage:           eapolkey.SMKMessage,
				KeyLength:            int32(eapolkey.KeyLength),
				ReplayCounter:        eapolkey.ReplayCounter,
				Nonce:                eapolkey.Nonce,
				IV:                   eapolkey.IV,
				RSC:                  eapolkey.RSC,
				ID:                   eapolkey.ID,
				MIC:                  eapolkey.MIC,
				KeyDataLength:        int32(eapolkey.KeyDataLength),
				EncryptedKeyData:     eapolkey.EncryptedKeyData,
			}
		}

		return nil
	},
)
