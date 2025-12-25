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
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/pkg/errors"
	"github.com/satta/gommunityid"

	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/decoder/stream"
	"github.com/dreadl0ck/netcap/defaults"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/internal/table"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

// GetPacketDecoders returns all available packet decoders
func GetPacketDecoders() []DecoderAPI {
	return defaultPacketDecoders
}

// GetGoPacketDecoders returns all available gopacket layer decoders
func GetGoPacketDecoders() []*GoPacketDecoder {
	return defaultGoPacketDecoders
}

var (
	typeMap      = make(map[string]int)
	fieldNameMap = make(map[string]int)
)

// MarkdownOverview dumps a Markdown summary of all available decoders and their fields.
func MarkdownOverview() {
	fmt.Println("# NETCAP Overview " + netcap.Version)
	fmt.Println("> Documentation: [docs.netcap.io](https://docs.netcap.io)")
	fmt.Println("## GoPacketDecoders")

	fmt.Println("|Name|NumFields|Fields|")
	fmt.Println("|----|---------|------|")
	for _, e := range defaultGoPacketDecoders {
		if csv, ok := netio.InitRecord(e.Type).(types.AuditRecord); ok {
			fmt.Println("|"+pad(e.Layer.String(), 30)+"|", len(csv.CSVHeader()), "|"+strings.Join(csv.CSVHeader(), ", ")+"|")
		}
	}

	fmt.Println("## PacketDecoders")

	fmt.Println("|Name|NumFields|Fields|")
	fmt.Println("|----|---------|------|")
	for _, d := range defaultPacketDecoders {
		if csv, ok := netio.InitRecord(d.GetType()).(types.AuditRecord); ok {
			fmt.Println("|"+pad(d.GetName(), 30)+"|", len(csv.CSVHeader()), "|"+strings.Join(csv.CSVHeader(), ", ")+"|")
		}
	}
}

//func recovery() {
//	if r := recover(); r != nil {
//		stream.errorsMapMutex.Lock()
//		stream.errorsMap[fmt.Sprint(r)]++
//		stream.errorsMapMutex.Unlock()
//	}
//}

func calcMd5(s string) string {
	var out []byte
	for _, b := range md5.Sum([]byte(s)) {
		out = append(out, b)
	}

	return hex.EncodeToString(out)
}

// communityIDGenerator is a reusable Community ID generator
// using the Corelight Community ID v1 specification.
// See: https://github.com/corelight/community-id-spec
var communityIDGenerator = gommunityid.CommunityIDv1{
	Seed: 0, // default seed
}

// CalcCommunityID generates a Community ID v1 for a packet.
// This provides a standardized flow identifier that is compatible
// with Zeek, Suricata, and other network monitoring tools.
// Returns an empty string if the packet lacks the necessary layers.
func CalcCommunityID(p gopacket.Packet) string {
	// Extract network layer for IP addresses
	nl := p.NetworkLayer()
	if nl == nil {
		return ""
	}

	var srcIP, dstIP net.IP
	var proto uint8

	// Extract IPs and protocol from network layer
	switch v := nl.(type) {
	case *layers.IPv4:
		srcIP = v.SrcIP
		dstIP = v.DstIP
		proto = uint8(v.Protocol)
	case *layers.IPv6:
		srcIP = v.SrcIP
		dstIP = v.DstIP
		proto = uint8(v.NextHeader)
	default:
		return ""
	}

	// Extract ports from transport layer
	var srcPort, dstPort uint16
	tl := p.TransportLayer()

	if tl != nil {
		switch v := tl.(type) {
		case *layers.TCP:
			srcPort = uint16(v.SrcPort)
			dstPort = uint16(v.DstPort)
		case *layers.UDP:
			srcPort = uint16(v.SrcPort)
			dstPort = uint16(v.DstPort)
		case *layers.SCTP:
			srcPort = uint16(v.SrcPort)
			dstPort = uint16(v.DstPort)
		default:
			// For transport layers we don't handle specifically,
			// try to get ports from raw data
			if len(tl.TransportFlow().Src().Raw()) >= 2 {
				srcPort = binary.BigEndian.Uint16(tl.TransportFlow().Src().Raw())
			}
			if len(tl.TransportFlow().Dst().Raw()) >= 2 {
				dstPort = binary.BigEndian.Uint16(tl.TransportFlow().Dst().Raw())
			}
		}
	}

	// Handle ICMP specially
	if icmpLayer := p.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmp := icmpLayer.(*layers.ICMPv4)
		ft := gommunityid.MakeFlowTupleICMP(srcIP, dstIP, uint16(icmp.TypeCode.Type()), uint16(icmp.TypeCode.Code()))
		return communityIDGenerator.CalcBase64(ft)
	}
	if icmpLayer := p.Layer(layers.LayerTypeICMPv6); icmpLayer != nil {
		icmp := icmpLayer.(*layers.ICMPv6)
		ft := gommunityid.MakeFlowTupleICMP6(srcIP, dstIP, uint16(icmp.TypeCode.Type()), uint16(icmp.TypeCode.Code()))
		return communityIDGenerator.CalcBase64(ft)
	}

	// Create flow tuple based on protocol
	var ft gommunityid.FlowTuple
	switch proto {
	case 6: // TCP
		ft = gommunityid.MakeFlowTupleTCP(srcIP, dstIP, srcPort, dstPort)
	case 17: // UDP
		ft = gommunityid.MakeFlowTupleUDP(srcIP, dstIP, srcPort, dstPort)
	case 132: // SCTP
		ft = gommunityid.MakeFlowTupleSCTP(srcIP, dstIP, srcPort, dstPort)
	default:
		// Generic flow tuple for other protocols
		ft = gommunityid.MakeFlowTuple(srcIP, dstIP, srcPort, dstPort, proto)
	}

	return communityIDGenerator.CalcBase64(ft)
}

func countFields(t types.Type) int {
	recordFields := 0
	if r, ok := netio.InitRecord(t).(types.AuditRecord); ok {

		auditRecord := reflect.ValueOf(r).Elem()

		// iterate over audit record fields
		for i := 0; i < auditRecord.NumField(); i++ { // get StructField
			field := auditRecord.Type().Field(i)
			fieldNameMap[field.Name]++

			switch field.Type.String() {
			case "string", "int32", "uint32", "bool", "int64", "uint64", "uint8", "float64":
				recordFields++
				// fmt.Println("  ", field.Name, field.Type, "1")
			default:
				if field.Type.Elem().Kind() == reflect.Struct {
					// fmt.Println("  ", field.Name, field.Type, field.Type.Elem().NumField())
					recordFields += field.Type.Elem().NumField()
					typeMap[strings.TrimPrefix(field.Type.String(), "*")] = field.Type.Elem().NumField()
				} else {
					if field.Type.Elem().Kind() == reflect.Ptr {
						recordFields += field.Type.Elem().Elem().NumField()
						// fmt.Println("  ", field.Name, field.Type, field.Type.Elem().Elem().NumField())
						typeMap[strings.TrimPrefix(strings.TrimPrefix(field.Type.String(), "[]"), "*")] = field.Type.Elem().Elem().NumField()
					} else {
						// scalar array types
						// fmt.Println("  ", field.Name, field.Type, "1")
						recordFields++
					}
				}
			}
		}
	}

	typeMap["types."+strings.TrimPrefix(t.String(), defaults.NetcapTypePrefix)] = recordFields

	return recordFields
}

func rankByWordCount(wordFrequencies map[string]int) pairList {
	pl := make(pairList, len(wordFrequencies))
	i := 0
	for k, v := range wordFrequencies {
		pl[i] = pair{k, v}
		i++
	}
	sort.Sort(sort.Reverse(pl))
	return pl
}

// pair describes a key and an associated value.
type pair struct {
	Key   string
	Value int
}

// pairList implements sort.Interface.
type pairList []pair

// Len will return the length.
func (p pairList) Len() int { return len(p) }

// Less will return true if the value at index i is smaller than the other one.
func (p pairList) Less(i, j int) bool { return p[i].Value < p[j].Value }

// Swap will switch the values.
func (p pairList) Swap(i, j int) { p[i], p[j] = p[j], p[i] }

// ApplyActionToPacketDecoders can be used to run custom code for all packet decoders.
func ApplyActionToPacketDecoders(action func(DecoderAPI)) {
	for _, d := range defaultPacketDecoders {
		action(d)
	}
}

// ApplyActionToPacketDecodersAsync can be used to run custom code for all packet decoders asynchronously.
func ApplyActionToPacketDecodersAsync(action func(DecoderAPI)) {

	// when debugging, enforce sequential processing so the logs are in order
	if decoderconfig.Instance.Debug {
		ApplyActionToPacketDecoders(action)
		return
	}

	wg := sync.WaitGroup{}
	for _, d := range defaultPacketDecoders {
		wg.Add(1)
		go func(d DecoderAPI) {
			action(d)
			wg.Done()
		}(d)
	}
	wg.Wait()
}

// ApplyActionToGoPacketDecoders can be used to run custom code for all gopacket decoders.
func ApplyActionToGoPacketDecoders(action func(*GoPacketDecoder)) {
	for _, e := range defaultGoPacketDecoders {
		action(e)
	}
}

// ApplyActionToGoPacketDecodersAsync can be used to run custom code for all gopacket decoders asynchronously.
func ApplyActionToGoPacketDecodersAsync(action func(*GoPacketDecoder)) {

	// when debugging, enforce sequential processing so the logs are in order
	if decoderconfig.Instance.Debug {
		ApplyActionToGoPacketDecoders(action)
		return
	}

	wg := sync.WaitGroup{}
	for _, d := range defaultGoPacketDecoders {
		wg.Add(1)
		go func(d *GoPacketDecoder) {
			action(d)
			wg.Done()
		}(d)
	}
	wg.Wait()
}

// ShowDecoders will dump all decoders to stdout.
func ShowDecoders(verbose bool) {

	fmt.Println("Format: Decoder Type ( Decoders / Number of Fields )")
	fmt.Println()

	var totalFields, totalAuditRecords int
	printDecoderStats := func(name string, d []core.DecoderAPI) {

		var newFields, newAuditRecords int
		var sum string

		for _, de := range d {
			newAuditRecords++
			f := countFields(de.GetType())
			newFields += f
			sum += pad("+ "+strings.TrimPrefix(de.GetType().String(), defaults.NetcapTypePrefix)+" ( "+strconv.Itoa(f)+" )", 35) + " " + de.GetDescription() + "\n"
		}

		fmt.Println(name+" Audit Records (", len(d), "/", newFields, ")")
		fmt.Println(sum)
		fmt.Println() // newline

		totalFields += newFields
		totalAuditRecords += newAuditRecords
	}

	printDecoderStats("Packet", func() []core.DecoderAPI {
		var res []core.DecoderAPI

		for _, s := range defaultPacketDecoders {
			res = append(res, s)
		}

		return res
	}())

	printDecoderStats("GoPacket", func() []core.DecoderAPI {
		var res []core.DecoderAPI

		for _, s := range defaultGoPacketDecoders {
			res = append(res, s)
		}

		return res
	}())

	printDecoderStats("Stream", func() []core.DecoderAPI {
		var res []core.DecoderAPI

		for _, s := range stream.DefaultStreamDecoders {
			res = append(res, s)
		}

		return res
	}())
	printDecoderStats("Abstract", stream.DefaultAbstractDecoders)

	// Dump Info

	if verbose {
		var rows [][]string
		for _, p := range rankByWordCount(typeMap)[:10] {
			rows = append(rows, []string{p.Key, strconv.Itoa(p.Value)})
		}

		fmt.Println("\nTypes with highest number of fields (Top Ten):")
		table.Render(os.Stdout, []string{"Type", "NumFields"}, rows)

		rows = [][]string{}
		for _, p := range rankByWordCount(fieldNameMap)[:10] {
			rows = append(rows, []string{p.Key, strconv.Itoa(p.Value)})
		}

		fmt.Println("\nFields with highest number of occurrences (Top Ten):")
		table.Render(os.Stdout, []string{"Name", "Count"}, rows)

		fmt.Println("> total fields: ", totalFields)
		fmt.Println("> total audit records:", totalAuditRecords)
		fmt.Println("> number of unique fields:", len(fieldNameMap))
	}
}

// entropy returns the shannon entropy value
// https://rosettacode.org/wiki/Entropy#Go
func entropy(data []byte) (entropy float64) {
	if len(data) == 0 {
		return 0
	}
	for i := 0; i < 256; i++ {
		px := float64(bytes.Count(data, []byte{byte(i)})) / float64(len(data))
		if px > 0 {
			entropy += -px * math.Log2(px)
		}
	}
	return entropy
}

const dot = byte('.')

func parseHexIPv4(ip []byte) string {

	var decoded = make([]byte, 4)

	_, err := hex.Decode(decoded, ip)
	if err != nil {
		return errors.Wrap(err, "raw="+hex.EncodeToString(ip)).Error()
	}

	var out []byte
	for i, c := range decoded {
		out = strconv.AppendInt(out, int64(c), 10)
		if i != 3 {
			out = append(out, dot)
		}
	}

	return string(out)
}

func parseIPv4(ip []byte) string {

	var out []byte
	for i, c := range ip {
		out = strconv.AppendInt(out, int64(c), 10)
		if i != 3 {
			out = append(out, dot)
		}
	}

	return string(out)
}

func formatHexMac(mac []byte) string {
	var (
		res          strings.Builder
		lastPosition = len(mac) - 1
	)
	for i, c := range mac {
		res.WriteByte(c)
		if (i+1)%2 == 0 && i != lastPosition {
			res.WriteString(":")
		}
	}

	return res.String()
}

func formatMac(mac []byte) string {

	var (
		encoded = hex.EncodeToString(mac)
		res     strings.Builder
	)
	for i, c := range encoded {
		res.WriteRune(c)
		if (i+1)%2 == 0 && i != 11 {
			res.WriteString(":")
		}
	}

	return res.String()
}

// pad the input up to the given number of space characters.
func pad(in interface{}, length int) string {
	return fmt.Sprintf("%-"+strconv.Itoa(length)+"s", in)
}

//func logReassemblyInfo(s string, a ...interface{}) {
//	if conf.Debug {
//		logger.ReassemblyLog.Printf("INFO: "+s, a...)
//	}
//}
//
//func logReassemblyDebug(s string, a ...interface{}) {
//	if conf.Debug {
//		logger.ReassemblyLog.Printf("DEBUG: "+s, a...)
//	}
//}

// TODO: add to general utils? or make a cryptoutils sub pkg?
//func loadRsaPrivKey(path string, rsaPrivateKeyPassword string) *rsa.PrivateKey {
//
//	priv, err := ioutil.ReadFile(path)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	privPem, _ := pem.Decode(priv)
//
//	var privPemBytes []byte
//	if privPem.Type != "RSA PRIVATE KEY" {
//		fmt.Println("RSA private key is of the wrong type", privPem.Type)
//	}
//
//	if rsaPrivateKeyPassword != "" {
//		privPemBytes, err = x509.DecryptPEMBlock(privPem, []byte(rsaPrivateKeyPassword))
//	} else {
//		privPemBytes = privPem.Bytes
//	}
//
//	var parsedKey interface{}
//	if parsedKey, err = x509.ParsePKCS1PrivateKey(privPemBytes); err != nil {
//		if parsedKey, err = x509.ParsePKCS8PrivateKey(privPemBytes); err != nil {
//			log.Fatal(err)
//		}
//	}
//
//	privateKey, ok := parsedKey.(*rsa.PrivateKey)
//	if !ok {
//		log.Fatal("not an rsa private key")
//	}
//	return privateKey
//}
