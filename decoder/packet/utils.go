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
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/pkg/errors"
	"math"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/decoder/stream"
	"github.com/dreadl0ck/netcap/defaults"

	"github.com/dreadl0ck/netcap"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
	"github.com/evilsocket/islazy/tui"
)

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
		tui.Table(os.Stdout, []string{"Type", "NumFields"}, rows)

		rows = [][]string{}
		for _, p := range rankByWordCount(fieldNameMap)[:10] {
			rows = append(rows, []string{p.Key, strconv.Itoa(p.Value)})
		}

		fmt.Println("\nFields with highest number of occurrences (Top Ten):")
		tui.Table(os.Stdout, []string{"Name", "Count"}, rows)

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
