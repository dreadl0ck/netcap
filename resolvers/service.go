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

package resolvers

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"go.uber.org/zap"
)

const (
	tcp      = "tcp"
	udp      = "udp"
	reserved = "Reserved"
)

// TODO: add a command to fetch the latest version
// https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv

// excerpt:
//Service Name,Port Number,Transport Protocol,Description,Assignee,Contact,Registration Date,Modification Date,Reference,Service Code,Unauthorized Use Reported,Assignment Notes
//,0,tcp,Reserved,[Jon_Postel],[Jon_Postel],,,,,,
//,0,udp,Reserved,[Jon_Postel],[Jon_Postel],,,,,,
//tcpmux,1,tcp,TCP Port Service Multiplexer,[Mark_Lottor],[Mark_Lottor],,,,,,
//tcpmux,1,udp,TCP Port Service Multiplexer,[Mark_Lottor],[Mark_Lottor],,,,,,
//compressnet,2,tcp,Management Utility,,,,,,,,
//compressnet,2,udp,Management Utility,,,,,,,,
//compressnet,3,tcp,Compression Process,[Bernie_Volz],[Bernie_Volz],,,,,,
//compressnet,3,udp,Compression Process,[Bernie_Volz],[Bernie_Volz],,,,,,

var (
	udpPortMap = make(map[int]port)
	tcpPortMap = make(map[int]port)
)

type port struct {
	service string
	num     int
}

var (
	pathReplacer  = strings.NewReplacer("/", "-", " ", "-", "]", "", "[", "", ")", "", "(", "", "---", "-", "-&-", "-")
	finalReplacer = strings.NewReplacer("---", "-", "-&-", "-")
)

func getServiceName(in string) string {
	name := strings.ToLower(in)
	name = pathReplacer.Replace(name)
	name = finalReplacer.Replace(name)
	return filepath.Clean(name)
}

// InitServiceDB initializes the ports to service names mapping.
// TODO: include service names for other transport protocols
func InitServiceDB() {
	var (
		f, err    = os.Open(filepath.Join(DataBaseFolderPath, "service-names-port-numbers.csv"))
		csvReader = csv.NewReader(f)
	)

	if err != nil {
		log.Println(err)
		return
	}

	defer func() {
		errClose := f.Close()
		if errClose != nil && !errors.Is(errClose, io.EOF) {
			fmt.Println("failed to close:", errClose)
		}
	}()

	records, err := csvReader.ReadAll()
	if err != nil {
		log.Fatal(err)
	}

	for i, r := range records { // skip CSV header
		if i == 0 {
			continue
		}

		// skip empty or broken records
		if r[1] == "" {
			continue
		}

		// handle ranges
		if strings.Contains(r[1], "-") {
			parts := strings.Split(r[1], "-")
			if len(parts) != 2 {
				fmt.Println("invalid parts length", parts)

				continue
			}

			start, errConvertStart := strconv.Atoi(parts[0])
			if errConvertStart != nil {
				fmt.Println(errConvertStart)

				continue
			}

			end, errConvertEnd := strconv.Atoi(parts[1])
			if errConvertEnd != nil {
				fmt.Println(errConvertEnd)

				continue
			}

			if end < start {
				fmt.Println("invalid range", parts)

				continue
			}

			if r[3] == reserved {
				continue
			}

			for index := start; index <= end; index++ {
				p := port{
					service: getServiceName(r[3]),
					num:     index,
				}

				switch {
				case r[2] == tcp:
					tcpPortMap[index] = p
				case r[2] == udp:
					udpPortMap[index] = p
				case r[3] == "Unassigned":
					// ignore
				default:
					resolverLog.Debug("ignoring service probe",
						zap.Strings("probe", r),
					)
				}
			}
		} else {
			// add port
			num, errPort := strconv.Atoi(r[1])
			if errPort != nil {
				fmt.Println(errPort)

				continue
			}

			if r[3] == reserved {
				continue
			}
			p := port{
				service: getServiceName(r[3]),
				num:     num,
			}

			switch {
			case r[2] == tcp:
				tcpPortMap[num] = p
			case r[2] == udp:
				udpPortMap[num] = p
			default:
				resolverLog.Debug("ignoring service probe",
					zap.Strings("probe", r),
				)
			}
		}
	}

	if !quiet {
		resolverLog.Info("loaded TCP service records", zap.Int("total", len(tcpPortMap)))
		resolverLog.Info("loaded UDP service records", zap.Int("total", len(udpPortMap)))
	}
}

// LookupServiceByPort looks up the service name associated with a given port and protocol.
func LookupServiceByPort(port int, protocol string) string {
	if protocol == "TCP" {
		if res, ok := tcpPortMap[port]; ok {
			return res.service
		}
	} else {
		if res, ok := udpPortMap[port]; ok {
			return res.service
		}
	}

	return ""
}
