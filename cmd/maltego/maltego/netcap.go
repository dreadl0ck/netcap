package maltego

import (
	"fmt"
	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type HTTPCountFunc = func(http *types.HTTP, minPackets, maxPackets *uint64)

type CountFunc = func(profile *types.DeviceProfile, mac string, minPackets, maxPackets *uint64)

var CountPacketsDevices = func(profile *types.DeviceProfile, mac string, minPackets, maxPackets *uint64) {
	if uint64(profile.NumPackets) < *minPackets {
		*minPackets = uint64(profile.NumPackets)
	}
	if uint64(profile.NumPackets) > *maxPackets {
		*maxPackets = uint64(profile.NumPackets)
	}
}

var CountPacketsDeviceIPs = func(profile *types.DeviceProfile, mac string, minPackets, maxPackets *uint64) {
	if profile.MacAddr == mac {
		for _, ip := range profile.DeviceIPs {
			if uint64(ip.NumPackets) < *minPackets {
				*minPackets = uint64(ip.NumPackets)
			}
			if uint64(ip.NumPackets) > *maxPackets {
				*maxPackets = uint64(ip.NumPackets)
			}
		}
	}
}

var CountPacketsContactIPs = func(profile *types.DeviceProfile, mac string, minPackets, maxPackets *uint64) {
	if profile.MacAddr == mac {
		for _, ip := range profile.Contacts {
			if uint64(ip.NumPackets) < *minPackets {
				*minPackets = uint64(ip.NumPackets)
			}
			if uint64(ip.NumPackets) > *maxPackets {
				*maxPackets = uint64(ip.NumPackets)
			}
		}
	}
}

type IPTransformationFunc = func(trx *MaltegoTransform, profile *types.DeviceProfile, min, max uint64, profilesFile string, mac string, ip string)

func IPTransform(count CountFunc, transform IPTransformationFunc) {

	lt := ParseLocalArguments(os.Args)
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
		minPackets uint64 = 10000000
		maxPackets uint64 = 0
	)

	if count != nil {

		for {
			err := r.Next(profile)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			} else if err != nil {
				panic(err)
			}

			count(profile, mac, &minPackets, &maxPackets)
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

		transform(&trx, profile, minPackets, maxPackets, profilesFile, mac, ipaddr)
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

	lt := ParseLocalArguments(os.Args)
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
		minPackets uint64 = 10000000
		maxPackets uint64 = 0
	)

	if count != nil {

		for {
			err := r.Next(profile)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			} else if err != nil {
				panic(err)
			}

			count(profile, mac, &minPackets, &maxPackets)
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

		transform(lt, &trx, profile, minPackets, maxPackets, profilesFile, mac)
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

	lt := ParseLocalArguments(os.Args)
	profilesFile := lt.Values["path"]
	ipaddr := lt.Values["ipaddr"]

	dir := filepath.Dir(profilesFile)
	httpAuditRecords := filepath.Join(dir, "HTTP.ncap.gz")
	f, err := os.Open(httpAuditRecords)
	if err != nil {
		log.Fatal(err)
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
		minPackets uint64 = 10000000
		maxPackets uint64 = 0
	)

	if count != nil {

		for {
			err := r.Next(http)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			} else if err != nil {
				panic(err)
			}

			count(http, &minPackets, &maxPackets)
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

		transform(lt, &trx, http, minPackets, maxPackets, profilesFile, ipaddr)
	}

	err = r.Close()
	if err != nil {
		log.Println("failed to close audit record file: ", err)
	}

	trx.AddUIMessage("completed!","Inform")
	fmt.Println(trx.ReturnOutput())
}


