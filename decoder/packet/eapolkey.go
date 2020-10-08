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
