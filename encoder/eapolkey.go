/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package encoder

import (
	"github.com/dreadl0ck/netcap/types"
	"github.com/golang/protobuf/proto"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var eapolkeyEncoder = CreateLayerEncoder(types.Type_NC_EAPOLKey, layers.LayerTypeEAPOLKey, func(layer gopacket.Layer, timestamp string) proto.Message {
	if eapolkey, ok := layer.(*layers.EAPOLKey); ok {
		return &types.EAPOLKey{
			Timestamp:            timestamp,
			KeyDescriptorType:    int32(eapolkey.KeyDescriptorType),
			KeyDescriptorVersion: int32(eapolkey.KeyDescriptorVersion),
			KeyType:              int32(eapolkey.KeyType),
			KeyIndex:             int32(eapolkey.KeyIndex),
			Install:              bool(eapolkey.Install),
			KeyACK:               bool(eapolkey.KeyACK),
			KeyMIC:               bool(eapolkey.KeyMIC),
			Secure:               bool(eapolkey.Secure),
			MICError:             bool(eapolkey.MICError),
			Request:              bool(eapolkey.Request),
			HasEncryptedKeyData:  bool(eapolkey.HasEncryptedKeyData),
			SMKMessage:           bool(eapolkey.SMKMessage),
			KeyLength:            int32(eapolkey.KeyLength),
			ReplayCounter:        uint64(eapolkey.ReplayCounter),
			Nonce:                []byte(eapolkey.Nonce),
			IV:                   []byte(eapolkey.IV),
			RSC:                  uint64(eapolkey.RSC),
			ID:                   uint64(eapolkey.ID),
			MIC:                  []byte(eapolkey.MIC),
			KeyDataLength:        int32(eapolkey.KeyDataLength),
			EncryptedKeyData:     []byte(eapolkey.EncryptedKeyData),
		}
	}
	return nil
})
