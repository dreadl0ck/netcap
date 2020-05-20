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
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/gogo/protobuf/proto"
	"github.com/mgutz/ansi"
	"github.com/sasha-s/go-deadlock"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type UDPStream struct {
	data UDPDataSlice
	deadlock.Mutex
}

type UDPData struct {
	raw       []byte
	ci        gopacket.CaptureInfo
	net       gopacket.Flow
	transport gopacket.Flow
}

var (
	udpStreams   = make(map[uint64]*UDPStream)
	udpStreamsMu deadlock.Mutex
)

// UDPDataSlice implements sort.Interface to sort data fragments based on their timestamps
type UDPDataSlice []*UDPData

func (d UDPDataSlice) Len() int {
	return len(d)
}
func (d UDPDataSlice) Less(i, j int) bool {
	data1 := d[i]
	data2 := d[j]
	return data1.ci.Timestamp.Before(data2.ci.Timestamp)
}
func (d UDPDataSlice) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}

// takes a udp packet and tracks the data seen for the conversation
func handleUDP(packet gopacket.Packet, udpLayer gopacket.Layer) {
	udpStreamsMu.Lock()
	if s, ok := udpStreams[packet.TransportLayer().TransportFlow().FastHash()]; ok {
		udpStreamsMu.Unlock()

		// update existing
		s.Lock()
		s.data = append(s.data, &UDPData{
			raw:       udpLayer.LayerPayload(),
			ci:        packet.Metadata().CaptureInfo,
			transport: packet.TransportLayer().TransportFlow(),
			net:       packet.NetworkLayer().NetworkFlow(),
		})
		s.Unlock()
	} else {
		// add new
		udpStreams[packet.TransportLayer().TransportFlow().FastHash()] = &UDPStream{
			data: []*UDPData{
				{
					raw:       udpLayer.LayerPayload(),
					ci:        packet.Metadata().CaptureInfo,
					transport: packet.TransportLayer().TransportFlow(),
					net:       packet.NetworkLayer().NetworkFlow(),
				},
			},
		}
		udpStreamsMu.Unlock()
	}
}

var udpEncoder = CreateLayerEncoder(types.Type_NC_UDP, layers.LayerTypeUDP, func(layer gopacket.Layer, timestamp string) proto.Message {
	if udp, ok := layer.(*layers.UDP); ok {
		var payload []byte
		if c.IncludePayloads {
			payload = layer.LayerPayload()
		}
		var e float64
		if c.CalculateEntropy {
			e = Entropy(udp.Payload)
		}
		return &types.UDP{
			Timestamp:      timestamp,
			SrcPort:        int32(udp.SrcPort),
			DstPort:        int32(udp.DstPort),
			Length:         int32(udp.Length),
			Checksum:       int32(udp.Checksum),
			PayloadEntropy: e,
			PayloadSize:    int32(len(udp.Payload)),
			Payload:        payload,
		}
	}
	return nil
})

func saveAllUDPConnections() {
	udpStreamsMu.Lock()
	for _, s := range udpStreams {
		s.Lock()
		sort.Sort(s.data)

		var (
			clientNetwork            gopacket.Flow
			clientTransport          gopacket.Flow
			firstPacket              time.Time
			colored                  bytes.Buffer
			raw                      bytes.Buffer
			ident                    string
			serverBytes, clientBytes int
		)

		// check who is client and who server based on first packet
		if len(s.data) > 0 {
			clientTransport = s.data[0].transport
			clientNetwork = s.data[0].net
			firstPacket = s.data[0].ci.Timestamp
			ident = filepath.Clean(fmt.Sprintf("%s-%s", clientNetwork, clientTransport))
		} else {
			// skip empty conns
			continue
		}

		var serverBanner bytes.Buffer

		for _, d := range s.data {
			if d.transport == clientTransport {
				clientBytes += len(d.raw)
				// client
				raw.Write(d.raw)
				colored.WriteString(ansi.Red)
				colored.Write(d.raw)
				colored.WriteString(ansi.Reset)
			} else {
				// server
				serverBytes += len(d.raw)
				for _, b := range d.raw {
					if serverBanner.Len() == c.BannerSize {
						break
					}
					serverBanner.WriteByte(b)
				}
				raw.Write(d.raw)
				colored.WriteString(ansi.Blue)
				colored.Write(d.raw)
				colored.WriteString(ansi.Reset)
			}
		}
		s.Unlock()

		// save stream data
		err := saveUDPConnection(raw.Bytes(), colored.Bytes(), ident, firstPacket, clientTransport)
		if err != nil {
			fmt.Println("failed to save UDP conn:", err)
		}

		// save service banner
		saveUDPServiceBanner(serverBanner.Bytes(), ident, clientNetwork.Dst().String()+":"+clientTransport.Dst().String(), firstPacket, serverBytes, clientBytes, clientNetwork, clientTransport)
	}
	udpStreamsMu.Unlock()
}

// saveUDPConnection saves the contents of a client server conversation via UDP to the filesystem
func saveUDPConnection(raw []byte, colored []byte, ident string, firstPacket time.Time, transport gopacket.Flow) error {

	// prevent processing zero bytes
	if len(raw) == 0 {
		return nil
	}

	banner := runHarvesters(raw, transport, ident, firstPacket)

	if !c.SaveConns {
		return nil
	}

	//fmt.Println("save conn", ident, len(raw), len(colored))
	//fmt.Println(string(colored))

	var (
		typ = getServiceName(banner, transport)

		// path for storing the data
		root = filepath.Join(c.Out, "udpConnections", typ)

		// file basename
		base = filepath.Clean(path.Base(ident)) + ".bin"
	)

	// make sure root path exists
	os.MkdirAll(root, directoryPermission)
	base = path.Join(root, base)

	utils.ReassemblyLog.Println("saveConnection", base)

	statsMutex.Lock()
	reassemblyStats.savedUDPConnections++
	statsMutex.Unlock()

	// append to files
	f, err := os.OpenFile(base, os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_SYNC, 0700)
	if err != nil {
		logReassemblyError("UDP conn create", "Cannot create %s: %s\n", base, err)
		return err
	}

	// do not colorize the data written to disk if its just a single keepalive byte
	if len(raw) == 1 {
		colored = raw
	}

	// save the colored version
	// assign a new buffer
	r := bytes.NewBuffer(colored)
	w, err := io.Copy(f, r)
	if err != nil {
		logReassemblyError("UDP stream", "%s: failed to save UDP conn %s (l:%d): %s\n", ident, base, w, err)
	} else {
		logReassemblyInfo("%s: Saved UDP conn %s (l:%d)\n", ident, base, w)
	}

	err = f.Close()
	if err != nil {
		logReassemblyError("UDP conn", "%s: failed to close UDP conn file %s (l:%d): %s\n", ident, base, w, err)
	}

	return nil
}

// saves the banner for a UDP service to the filesystem
// and limits the length of the saved data to the BannerSize value from the config
func saveUDPServiceBanner(banner []byte, flowIdent string, serviceIdent string, firstPacket time.Time, serverBytes int, clientBytes int, net gopacket.Flow, transport gopacket.Flow) {

	// limit length of data
	if len(banner) >= c.BannerSize {
		banner = banner[:c.BannerSize]
	}

	// check if we already have a banner for the IP + Port combination
	ServiceStore.Lock()
	if serv, ok := ServiceStore.Items[serviceIdent]; ok {
		defer ServiceStore.Unlock()

		for _, f := range serv.Flows {
			if f == flowIdent {
				return
			}
		}

		serv.Flows = append(serv.Flows, flowIdent)
		return
	}
	ServiceStore.Unlock()

	// nope. lets create a new one
	serv := NewService(firstPacket.String(), serverBytes, clientBytes, net.Dst().String())
	serv.Banner = banner
	serv.IP = net.Dst().String()
	serv.Port = transport.Dst().String()

	// set flow ident, h.parent.ident is the client flow
	serv.Flows = []string{flowIdent}

	dst, err := strconv.Atoi(transport.Dst().String())
	if err == nil {
		serv.Protocol = "UDP"
		serv.Name = resolvers.LookupServiceByPort(dst, "udp")
	}

	// match banner against nmap service probes
	for _, serviceProbe := range serviceProbes {
		if c.UseRE2 {
			if m := serviceProbe.RegEx.FindStringSubmatch(string(banner)); m != nil {

				serv.Product = addInfo(serv.Product, serviceProbe.Ident)
				serv.Vendor = addInfo(serv.Vendor, serviceProbe.Vendor)
				serv.Version = addInfo(serv.Version, serviceProbe.Version)

				if strings.Contains(serviceProbe.Version, "$1") {
					if len(m) > 1 {
						serv.Version = addInfo(serv.Version, strings.Replace(serviceProbe.Version, "$1", m[1], 1))
					}
				}

				if strings.Contains(serviceProbe.Hostname, "$1") {
					if len(m) > 1 {
						serv.Notes = addInfo(serv.Notes, strings.Replace(serviceProbe.Hostname, "$1", m[1], 1))
					}
				}

				// TODO: make a group extraction util and expand all groups in all strings properly
				if strings.Contains(serviceProbe.Info, "$1") {
					if len(m) > 1 {
						serv.Product = addInfo(serv.Product, strings.Replace(serviceProbe.Info, "$1", m[1], 1))
					}
				}
				if strings.Contains(serv.Product, "$2") {
					if len(m) > 2 {
						serv.Product = addInfo(serv.Product, strings.Replace(serviceProbe.Info, "$2", m[2], 1))
					}
				}

				if c.Debug {
					fmt.Println("\n\nMATCH!", flowIdent)
					fmt.Println(serviceProbe, "\nBanner:", "\n"+hex.Dump(banner))
				}
			}
		} else {
			if m, err := serviceProbe.RegEx2.FindStringMatch(string(banner)); err == nil && m != nil {

				serv.Product = addInfo(serv.Product, serviceProbe.Ident)
				serv.Vendor = addInfo(serv.Vendor, serviceProbe.Vendor)
				serv.Version = addInfo(serv.Version, serviceProbe.Version)

				if strings.Contains(serviceProbe.Version, "$1") {
					if len(m.Groups()) > 1 {
						serv.Version = addInfo(serv.Version, strings.Replace(serviceProbe.Version, "$1", m.Groups()[1].Captures[0].String(), 1))
					}
				}

				// TODO: make a group extraction util
				if strings.Contains(serviceProbe.Info, "$1") {
					if len(m.Groups()) > 1 {
						serv.Product = addInfo(serv.Product, strings.Replace(serviceProbe.Info, "$1", m.Groups()[1].Captures[0].String(), 1))
					}
				}
				if strings.Contains(serv.Product, "$2") {
					if len(m.Groups()) > 2 {
						serv.Product = addInfo(serv.Product, strings.Replace(serviceProbe.Info, "$2", m.Groups()[2].Captures[0].String(), 1))
					}
				}

				if c.Debug {
					fmt.Println("\nMATCH!", flowIdent)
					fmt.Println(serviceProbe, "\nBanner:", "\n"+hex.Dump(banner))
				}
			}
		}
	}

	// add new service
	ServiceStore.Lock()
	ServiceStore.Items[serviceIdent] = serv
	ServiceStore.Unlock()

	statsMutex.Lock()
	reassemblyStats.numServices++
	statsMutex.Unlock()
}
