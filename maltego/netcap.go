package maltego

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func EscapeText(text string) string {
	var buf bytes.Buffer
	err := xml.EscapeText(&buf, []byte(text))
	if err != nil {
		fmt.Println(err)
	}
	return buf.String()
}

type HTTPCountFunc = func(http *types.HTTP, min, max *uint64)

type CountFunc = func(profile *types.DeviceProfile, mac string, min, max *uint64)

var CountPacketsDevices = func(profile *types.DeviceProfile, mac string, min, max *uint64) {
	if uint64(profile.NumPackets) < *min {
		*min = uint64(profile.NumPackets)
	}
	if uint64(profile.NumPackets) > *max {
		*max = uint64(profile.NumPackets)
	}
}

var CountPacketsDeviceIPs = func(profile *types.DeviceProfile, mac string, min, max *uint64) {
	if profile.MacAddr == mac {
		for _, ip := range profile.DeviceIPs {
			if uint64(ip.NumPackets) < *min {
				*min = uint64(ip.NumPackets)
			}
			if uint64(ip.NumPackets) > *max {
				*max = uint64(ip.NumPackets)
			}
		}
	}
}

var CountPacketsContactIPs = func(profile *types.DeviceProfile, mac string, min, max *uint64) {
	if profile.MacAddr == mac {
		for _, ip := range profile.Contacts {
			if uint64(ip.NumPackets) < *min {
				*min = uint64(ip.NumPackets)
			}
			if uint64(ip.NumPackets) > *max {
				*max = uint64(ip.NumPackets)
			}
		}
	}
}

type IPTransformationFunc = func(lt LocalTransform, trx *MaltegoTransform, profile *types.DeviceProfile, min, max uint64, profilesFile string, mac string, ip string)

func IPTransform(count CountFunc, transform IPTransformationFunc) {

	lt := ParseLocalArguments(os.Args[1:])
	profilesFile := lt.Values["path"]
	mac := lt.Values["mac"]
	ipaddr := lt.Values["ipaddr"]

	stdout := os.Stdout
	os.Stdout = os.Stderr
	netcap.PrintBuildInfo()

	f, err := os.Open(profilesFile)
	if err != nil {
		log.Fatal(err)
	}

	// check if its an audit record file
	if !strings.HasSuffix(f.Name(), ".ncap.gz") && !strings.HasSuffix(f.Name(), ".ncap") {
		log.Fatal("input file must be an audit record file")
	}

	os.Stdout = stdout

	r, err := netcap.Open(profilesFile, netcap.DefaultBufferSize)
	if err != nil {
		panic(err)
	}

	// read netcap header
	header := r.ReadHeader()
	if header.Type != types.Type_NC_DeviceProfile {
		panic("file does not contain DeviceProfile records: " + header.Type.String())
	}

	var (
		profile = new(types.DeviceProfile)
		pm  proto.Message
		ok  bool
		trx = MaltegoTransform{}
	)
	pm = profile

	if _, ok = pm.(types.AuditRecord); !ok {
		panic("type does not implement types.AuditRecord interface")
	}

	var (
		min uint64 = 10000000
		max uint64 = 0
	)

	if count != nil {

		for {
			err := r.Next(profile)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			} else if err != nil {
				panic(err)
			}

			count(profile, mac, &min, &max)
		}

		err = r.Close()
		if err != nil {
			log.Println("failed to close audit record file: ", err)
		}
	}


	r, err = netcap.Open(profilesFile, netcap.DefaultBufferSize)
	if err != nil {
		panic(err)
	}

	// read netcap header - ignore err as it has been checked before
	r.ReadHeader()

	for {
		err := r.Next(profile)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			panic(err)
		}

		transform(lt, &trx, profile, min, max, profilesFile, mac, ipaddr)
	}

	err = r.Close()
	if err != nil {
		log.Println("failed to close audit record file: ", err)
	}

	trx.AddUIMessage("completed!","Inform")
	fmt.Println(trx.ReturnOutput())
}

type DeviceProfileTransformationFunc = func(lt LocalTransform, trx *MaltegoTransform, profile *types.DeviceProfile, min, max uint64, profilesFile string, mac string)

func DeviceProfileTransform(count CountFunc, transform DeviceProfileTransformationFunc) {

	lt := ParseLocalArguments(os.Args[1:])
	profilesFile := lt.Values["path"]
	mac := lt.Values["mac"]

	stdout := os.Stdout
	os.Stdout = os.Stderr
	netcap.PrintBuildInfo()

	f, err := os.Open(profilesFile)
	if err != nil {
		log.Fatal(err)
	}

	// check if its an audit record file
	if !strings.HasSuffix(f.Name(), ".ncap.gz") && !strings.HasSuffix(f.Name(), ".ncap") {
		log.Fatal("input file must be an audit record file")
	}

	os.Stdout = stdout

	r, err := netcap.Open(profilesFile, netcap.DefaultBufferSize)
	if err != nil {
		panic(err)
	}

	// read netcap header
	header := r.ReadHeader()
	if header.Type != types.Type_NC_DeviceProfile {
		panic("file does not contain DeviceProfile records: " + header.Type.String())
	}

	var (
		profile = new(types.DeviceProfile)
		pm  proto.Message
		ok  bool
		trx = MaltegoTransform{}
	)
	pm = profile

	if _, ok = pm.(types.AuditRecord); !ok {
		panic("type does not implement types.AuditRecord interface")
	}

	var (
		min uint64 = 10000000
		max uint64 = 0
	)

	if count != nil {

		for {
			err := r.Next(profile)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			} else if err != nil {
				panic(err)
			}

			count(profile, mac, &min, &max)
		}

		err = r.Close()
		if err != nil {
			log.Println("failed to close audit record file: ", err)
		}

		r, err = netcap.Open(profilesFile, netcap.DefaultBufferSize)
		if err != nil {
			panic(err)
		}

		// read netcap header - ignore err as it has been checked before
		r.ReadHeader()
	}

	for {
		err := r.Next(profile)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			panic(err)
		}

		transform(lt, &trx, profile, min, max, profilesFile, mac)
	}

	err = r.Close()
	if err != nil {
		log.Println("failed to close audit record file: ", err)
	}

	trx.AddUIMessage("completed!","Inform")
	fmt.Println(trx.ReturnOutput())
}

type HTTPTransformationFunc = func(lt LocalTransform, trx *MaltegoTransform, http *types.HTTP, min, max uint64, profilesFile string, ip string)

func HTTPTransform(count HTTPCountFunc, transform HTTPTransformationFunc) {

	lt := ParseLocalArguments(os.Args[1:])
	profilesFile := lt.Values["path"]
	ipaddr := lt.Values["ipaddr"]

	dir := filepath.Dir(profilesFile)
	httpAuditRecords := filepath.Join(dir, "HTTP.ncap.gz")
	f, err := os.Open(httpAuditRecords)
	if err != nil {
		// write an empty reply if the audit record file was not found.
		log.Println(err)
		trx := MaltegoTransform{}
		fmt.Println(trx.ReturnOutput())
		return
	}

	// check if its an audit record file
	if !strings.HasSuffix(f.Name(), ".ncap.gz") && !strings.HasSuffix(f.Name(), ".ncap") {
		log.Fatal("input file must be an audit record file")
	}

	r, err := netcap.Open(httpAuditRecords, netcap.DefaultBufferSize)
	if err != nil {
		panic(err)
	}

	// read netcap header
	header := r.ReadHeader()
	if header.Type != types.Type_NC_HTTP {
		panic("file does not contain HTTP records: " + header.Type.String())
	}

	var (
		http = new(types.HTTP)
		pm  proto.Message
		ok  bool
		trx = MaltegoTransform{}
	)
	pm = http

	if _, ok = pm.(types.AuditRecord); !ok {
		panic("type does not implement types.AuditRecord interface")
	}

	var (
		min uint64 = 10000000
		max uint64 = 0
	)

	if count != nil {

		for {
			err := r.Next(http)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			} else if err != nil {
				panic(err)
			}

			count(http, &min, &max)
		}

		err = r.Close()
		if err != nil {
			log.Println("failed to close audit record file: ", err)
		}
	}


	r, err = netcap.Open(httpAuditRecords, netcap.DefaultBufferSize)
	if err != nil {
		panic(err)
	}

	// read netcap header - ignore err as it has been checked before
	r.ReadHeader()

	for {
		err := r.Next(http)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			panic(err)
		}

		transform(lt, &trx, http, min, max, profilesFile, ipaddr)
	}

	err = r.Close()
	if err != nil {
		log.Println("failed to close audit record file: ", err)
	}

	trx.AddUIMessage("completed!","Inform")
	fmt.Println(trx.ReturnOutput())
}

type FilesCountFunc func()
type FilesTransformationFunc = func(lt LocalTransform, trx *MaltegoTransform, file *types.File, min, max uint64, profilesFile string, ip string)

func FilesTransform(count FilesCountFunc, transform FilesTransformationFunc) {

	lt := ParseLocalArguments(os.Args[1:])
	profilesFile := lt.Values["path"]
	ipaddr := lt.Values["ipaddr"]

	dir := filepath.Dir(profilesFile)
	httpAuditRecords := filepath.Join(dir, "File.ncap.gz")
	f, err := os.Open(httpAuditRecords)
	if err != nil {
		// write an empty reply if the audit record file was not found.
		log.Println(err)
		trx := MaltegoTransform{}
		fmt.Println(trx.ReturnOutput())
		return
	}

	// check if its an audit record file
	if !strings.HasSuffix(f.Name(), ".ncap.gz") && !strings.HasSuffix(f.Name(), ".ncap") {
		log.Fatal("input file must be an audit record file")
	}

	r, err := netcap.Open(httpAuditRecords, netcap.DefaultBufferSize)
	if err != nil {
		panic(err)
	}

	// read netcap header
	header := r.ReadHeader()
	if header.Type != types.Type_NC_File {
		panic("file does not contain File records: " + header.Type.String())
	}

	var (
		file = new(types.File)
		pm  proto.Message
		ok  bool
		trx = MaltegoTransform{}
	)
	pm = file

	if _, ok = pm.(types.AuditRecord); !ok {
		panic("type does not implement types.AuditRecord interface")
	}

	var (
		min uint64 = 10000000
		max uint64 = 0
	)

	if count != nil {

		for {
			err := r.Next(file)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			} else if err != nil {
				panic(err)
			}

			count()
		}

		err = r.Close()
		if err != nil {
			log.Println("failed to close audit record file: ", err)
		}
	}


	r, err = netcap.Open(httpAuditRecords, netcap.DefaultBufferSize)
	if err != nil {
		panic(err)
	}

	// read netcap header - ignore err as it has been checked before
	r.ReadHeader()

	for {
		err := r.Next(file)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			panic(err)
		}

		transform(lt, &trx, file, min, max, profilesFile, ipaddr)
	}

	err = r.Close()
	if err != nil {
		log.Println("failed to close audit record file: ", err)
	}

	trx.AddUIMessage("completed!","Inform")
	fmt.Println(trx.ReturnOutput())
}

type POP3CountFunc func()
type POP3TransformationFunc = func(lt LocalTransform, trx *MaltegoTransform, pop3 *types.POP3, min, max uint64, profilesFile string, ip string)

func POP3Transform(count POP3CountFunc, transform POP3TransformationFunc) {

	lt := ParseLocalArguments(os.Args[1:])
	profilesFile := lt.Values["path"]
	ipaddr := lt.Values["ipaddr"]

	dir := filepath.Dir(profilesFile)
	httpAuditRecords := filepath.Join(dir, "POP3.ncap.gz")
	f, err := os.Open(httpAuditRecords)
	if err != nil {
		// write an empty reply if the audit record file was not found.
		log.Println(err)
		trx := MaltegoTransform{}
		fmt.Println(trx.ReturnOutput())
		return
	}

	// check if its an audit record file
	if !strings.HasSuffix(f.Name(), ".ncap.gz") && !strings.HasSuffix(f.Name(), ".ncap") {
		log.Fatal("input file must be an audit record file")
	}

	r, err := netcap.Open(httpAuditRecords, netcap.DefaultBufferSize)
	if err != nil {
		panic(err)
	}

	// read netcap header
	header := r.ReadHeader()
	if header.Type != types.Type_NC_POP3 {
		panic("file does not contain POP3 records: " + header.Type.String())
	}

	var (
		pop3 = new(types.POP3)
		pm  proto.Message
		ok  bool
		trx = MaltegoTransform{}
	)
	pm = pop3

	if _, ok = pm.(types.AuditRecord); !ok {
		panic("type does not implement types.AuditRecord interface")
	}

	var (
		min uint64 = 10000000
		max uint64 = 0
	)

	if count != nil {

		for {
			err := r.Next(pop3)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			} else if err != nil {
				panic(err)
			}

			count()
		}

		err = r.Close()
		if err != nil {
			log.Println("failed to close audit record file: ", err)
		}
	}


	r, err = netcap.Open(httpAuditRecords, netcap.DefaultBufferSize)
	if err != nil {
		panic(err)
	}

	// read netcap header - ignore err as it has been checked before
	r.ReadHeader()

	for {
		err := r.Next(pop3)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			panic(err)
		}

		transform(lt, &trx, pop3, min, max, profilesFile, ipaddr)
	}

	err = r.Close()
	if err != nil {
		log.Println("failed to close audit record file: ", err)
	}

	trx.AddUIMessage("completed!","Inform")
	fmt.Println(trx.ReturnOutput())
}

type DHCPCountFunc func()
type DHCPTransformationFunc = func(lt LocalTransform, trx *MaltegoTransform, dhcp *types.DHCPv4, min, max uint64, profilesFile string, ip string)

func DHCPTransform(count DHCPCountFunc, transform DHCPTransformationFunc) {

	lt := ParseLocalArguments(os.Args[1:])
	profilesFile := lt.Values["path"]
	ipaddr := lt.Values["ipaddr"]

	dir := filepath.Dir(profilesFile)
	httpAuditRecords := filepath.Join(dir, "DHCPv4.ncap.gz")
	f, err := os.Open(httpAuditRecords)
	if err != nil {
		log.Println(err)
		trx := MaltegoTransform{}
		fmt.Println(trx.ReturnOutput())
		return
	}

	// check if its an audit record file
	if !strings.HasSuffix(f.Name(), ".ncap.gz") && !strings.HasSuffix(f.Name(), ".ncap") {
		log.Fatal("input file must be an audit record file")
	}

	r, err := netcap.Open(httpAuditRecords, netcap.DefaultBufferSize)
	if err != nil {
		panic(err)
	}

	// read netcap header
	header := r.ReadHeader()
	if header.Type != types.Type_NC_DHCPv4 {
		panic("file does not contain DHCPv4 records: " + header.Type.String())
	}

	var (
		dhcp = new(types.DHCPv4)
		pm  proto.Message
		ok  bool
		trx = MaltegoTransform{}
	)
	pm = dhcp

	if _, ok = pm.(types.AuditRecord); !ok {
		panic("type does not implement types.AuditRecord interface")
	}

	var (
		min uint64 = 10000000
		max uint64 = 0
	)

	if count != nil {

		for {
			err := r.Next(dhcp)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			} else if err != nil {
				panic(err)
			}

			count()
		}

		err = r.Close()
		if err != nil {
			log.Println("failed to close audit record file: ", err)
		}
	}


	r, err = netcap.Open(httpAuditRecords, netcap.DefaultBufferSize)
	if err != nil {
		panic(err)
	}

	// read netcap header - ignore err as it has been checked before
	r.ReadHeader()

	for {
		err := r.Next(dhcp)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			panic(err)
		}

		transform(lt, &trx, dhcp, min, max, profilesFile, ipaddr)
	}

	err = r.Close()
	if err != nil {
		log.Println("failed to close audit record file: ", err)
	}

	trx.AddUIMessage("completed!","Inform")
	fmt.Println(trx.ReturnOutput())
}

type FlowCountFunc = func(flow *types.Flow, ipaddr string, min, max *uint64, sizes *[]int)

var CountIncomingFlowBytes = func(flow *types.Flow, ipaddr string, min, max *uint64, sizes *[]int) {
	if flow.DstIP == ipaddr {

		*sizes = append(*sizes, int(flow.TotalSize))

		if uint64(flow.TotalSize) < *min {
			*min = uint64(flow.TotalSize)
		}
		if uint64(flow.TotalSize) > *max {
			*max = uint64(flow.TotalSize)
		}
	}
}

var CountIncomingFlowBytesFiltered = func(flow *types.Flow, ipaddr string, min, max *uint64, sizes *[]int) {
	if flow.DstIP == ipaddr {
		name := resolvers.LookupDNSNameLocal(flow.SrcIP)
		if name != "" {
			if !resolvers.IsWhitelisted(name) {
				*sizes = append(*sizes, int(flow.TotalSize))

				if uint64(flow.TotalSize) < *min {
					*min = uint64(flow.TotalSize)
				}
				if uint64(flow.TotalSize) > *max {
					*max = uint64(flow.TotalSize)
				}
			}
		} else {
			// bare IP
			*sizes = append(*sizes, int(flow.TotalSize))

			if uint64(flow.TotalSize) < *min {
				*min = uint64(flow.TotalSize)
			}
			if uint64(flow.TotalSize) > *max {
				*max = uint64(flow.TotalSize)
			}
		}
	}
}

var CountIncomingFlowPackets = func(flow *types.Flow, ipaddr string, min, max *uint64, sizes *[]int) {
	if flow.DstIP == ipaddr {

		*sizes = append(*sizes, int(flow.TotalSize))

		if uint64(flow.NumPackets) < *min {
			*min = uint64(flow.NumPackets)
		}
		if uint64(flow.NumPackets) > *max {
			*max = uint64(flow.NumPackets)
		}
	}
}

var CountOutgoingFlowBytes = func(flow *types.Flow, ipaddr string, min, max *uint64, sizes *[]int) {
	if flow.SrcIP == ipaddr {

		*sizes = append(*sizes, int(flow.TotalSize))

		if uint64(flow.TotalSize) < *min {
			*min = uint64(flow.TotalSize)
		}
		if uint64(flow.TotalSize) > *max {
			*max = uint64(flow.TotalSize)
		}
	}
}

var CountOutgoingFlowBytesFiltered = func(flow *types.Flow, ipaddr string, min, max *uint64, sizes *[]int) {
	if flow.SrcIP == ipaddr {
		name := resolvers.LookupDNSNameLocal(flow.DstIP)
		if name != "" {
			if !resolvers.IsWhitelisted(name) {
				*sizes = append(*sizes, int(flow.TotalSize))

				if uint64(flow.TotalSize) < *min {
					*min = uint64(flow.TotalSize)
				}
				if uint64(flow.TotalSize) > *max {
					*max = uint64(flow.TotalSize)
				}
			}
		} else {
			// bare IP
			*sizes = append(*sizes, int(flow.TotalSize))

			if uint64(flow.TotalSize) < *min {
				*min = uint64(flow.TotalSize)
			}
			if uint64(flow.TotalSize) > *max {
				*max = uint64(flow.TotalSize)
			}
		}
	}
}

var CountOutgoingFlowPackets = func(flow *types.Flow, ipaddr string, min, max *uint64, sizes *[]int) {
	if flow.SrcIP == ipaddr {

		*sizes = append(*sizes, int(flow.TotalSize))

		if uint64(flow.NumPackets) < *min {
			*min = uint64(flow.NumPackets)
		}
		if uint64(flow.NumPackets) > *max {
			*max = uint64(flow.NumPackets)
		}
	}
}

type FlowTransformationFunc = func(lt LocalTransform, trx *MaltegoTransform, flow *types.Flow, min, max uint64, profilesFile string, mac string, ip string, sizes *[]int)

func FlowTransform(count FlowCountFunc, transform FlowTransformationFunc) {

	lt := ParseLocalArguments(os.Args[1:])
	profilesFile := lt.Values["path"]
	mac := lt.Values["mac"]
	ipaddr := lt.Values["ipaddr"]

	stdout := os.Stdout
	os.Stdout = os.Stderr
	netcap.PrintBuildInfo()

	dir := filepath.Dir(profilesFile)
	flowAuditRecords := filepath.Join(dir, "Flow.ncap.gz")
	log.Println("open", flowAuditRecords)
	f, err := os.Open(flowAuditRecords)
	if err != nil {
		log.Fatal(err)
	}

	// check if its an audit record file
	if !strings.HasSuffix(f.Name(), ".ncap.gz") && !strings.HasSuffix(f.Name(), ".ncap") {
		log.Fatal("input file must be an audit record file")
	}

	os.Stdout = stdout

	r, err := netcap.Open(flowAuditRecords, netcap.DefaultBufferSize)
	if err != nil {
		panic(err)
	}

	// read netcap header
	header := r.ReadHeader()
	if header.Type != types.Type_NC_Flow {
		panic("file does not contain Flow records: " + header.Type.String())
	}

	var (
		flow = new(types.Flow)
		pm  proto.Message
		ok  bool
		trx = MaltegoTransform{}
	)
	pm = flow

	if _, ok = pm.(types.AuditRecord); !ok {
		panic("type does not implement types.AuditRecord interface")
	}

	var (
		min uint64 = 10000000
		max uint64 = 0
		sizes []int
	)

	if count != nil {

		for {
			err := r.Next(flow)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			} else if err != nil {
				panic(err)
			}

			count(flow, ipaddr, &min, &max, &sizes)
		}

		err = r.Close()
		if err != nil {
			log.Println("failed to close audit record file: ", err)
		}

		sort.Ints(sizes)
	}

	r, err = netcap.Open(flowAuditRecords, netcap.DefaultBufferSize)
	if err != nil {
		panic(err)
	}

	// read netcap header - ignore err as it has been checked before
	r.ReadHeader()

	top12 := sizes[len(sizes)-13:]
	log.Println("==> top12", top12)

	for {
		err := r.Next(flow)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			panic(err)
		}

		transform(lt, &trx, flow, min, max, profilesFile, mac, ipaddr, &top12)
	}

	err = r.Close()
	if err != nil {
		log.Println("failed to close audit record file: ", err)
	}

	trx.AddUIMessage("completed!","Inform")
	fmt.Println(trx.ReturnOutput())
}