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

package encoder

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/dreadl0ck/netcap/sshx"
	"github.com/dreadl0ck/netcap/types"
	"strings"
)

/*
* TCP
*/

type sshReader struct {
	parent   *tcpConnection
}

func (h *sshReader) Decode(s2c Stream, c2s Stream) {

	r := bufio.NewReader(bytes.NewReader(h.parent.ConversationRaw()))

	for {

		data, _, err := r.ReadLine()
		if err != nil {
			break
		}

		//fmt.Println(hex.Dump(data))

		for i, b := range data {

			if b == 0x14 { // Marks the beginning of the KexInitMsg // TODO: stop checking after X bytes, and after we already have server and client hashes

				if i == 0 {
					break
				}

				if len(data[:i-1]) != 4 {
					break
				}

				length := int(binary.BigEndian.Uint32(data[:i-1]))
				padding := int(data[i-1])
				if len(data) < i+length-padding-1 {
					break
				}

				//fmt.Println("padding", padding, "length", length)
				//fmt.Println(hex.Dump(data[i:i+length-padding-1]))

				var init sshx.KexInitMsg
				err := sshx.Unmarshal(data[i:i+length-padding-1], &init)
				if err != nil {
					fmt.Println(err)
				}

				spew.Dump("found SSH KexInit", h.parent.ident, init)
				hash, raw := computeHASSH(init)

				sshEncoder.write(&types.SSH{
					Timestamp:  h.parent.client.FirstPacket().String(),
					HASSH:      hash,
					Flow:       h.parent.ident,
					Notes:      "",
					Ident:      "", // TODO: add open ssh self ident
					Algorithms: raw,
				})
				break
			}
		}
	}
}

func computeHASSH(init sshx.KexInitMsg) (hash string, raw string) {

	var b strings.Builder
	b.WriteString(strings.Join(init.KexAlgos, ","))
	b.WriteString(";")
	b.WriteString(strings.Join(init.CiphersClientServer, ","))
	b.WriteString(";")
	b.WriteString(strings.Join(init.MACsClientServer, ","))
	b.WriteString(";")
	b.WriteString(strings.Join(init.CompressionClientServer, ","))

	return fmt.Sprintf("%x", md5.Sum([]byte(b.String()))), b.String()
}
