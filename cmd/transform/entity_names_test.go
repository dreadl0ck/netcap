package transform

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestGoPacketEntityNamesFollowWriterFiles(t *testing.T) {
	names := goPacketEntityNames()
	for file, entity := range map[string]string{"GTP": "GTPv1U", "VRRP": "VRRP", "ApplePktap": "ApplePktap", "PTPv2": "PTP", "SampledValues": "SV", "GOOSE": "GOOSE", "OPCUAPubSub": "OPCUAPubSub"} {
		if names[file] != entity {
			t.Errorf("%s.ncap.gz maps to entity %q, want %q", file, names[file], entity)
		}
	}
	for file, entity := range names {
		if entity == "ApplePktap" {
			continue // PKTAP has never had a Maltego entity.
		}
		path := filepath.Join("..", "..", "internal", "maltego", "netcap", "Entities", "netcap."+entity+"AuditRecords.entity")
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s.ncap.gz has no AuditRecords entity: %v", file, err)
		}
	}
}

func TestIndustrialMaltegoArchive(t *testing.T) {
	base := filepath.Join("..", "..", "internal", "maltego")
	z, err := zip.OpenReader(filepath.Join(base, "netcap.mtz"))
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	for file, entity := range map[string]string{"PTPv2": "PTP", "SampledValues": "SV", "GOOSE": "GOOSE", "OPCUAPubSub": "OPCUAPubSub", "EtherCAT": "EtherCAT", "IEC104": "IEC104", "AMS": "AMS", "MMS": "MMS"} {
		id := "netcap." + entity + "AuditRecords"
		path := "Entities/" + id + ".entity"
		installed, err := fs.ReadFile(z, path)
		if err != nil {
			t.Fatal(err)
		}
		source, err := os.ReadFile(filepath.Join(base, "netcap", path))
		if err != nil || !bytes.Equal(source, installed) {
			t.Fatalf("%s differs from the shipped archive: %v", path, err)
		}
		var def struct {
			ID      string `xml:"id,attr"`
			Pattern string `xml:"Converter>Value"`
		}
		if err := xml.Unmarshal(installed, &def); err != nil || def.ID != id {
			t.Fatalf("%s: %+v, %v", path, def, err)
		}
		re, err := regexp.Compile(def.Pattern)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"out/" + file + ".ncap", `C:\out\` + file + ".ncap.gz"} {
			if m := re.FindStringSubmatch(name); len(m) < 4 || m[1] != name || m[3] != file {
				t.Errorf("%s: converter %q does not extract %q", id, re, name)
			}
		}
	}
}
