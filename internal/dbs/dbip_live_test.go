package dbs

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestDBIPLiveDownloadLookupAndArchive(t *testing.T) {
	if os.Getenv("NETCAP_GEOIP_LIVE_TEST") != "1" {
		t.Skip("set NETCAP_GEOIP_LIVE_TEST=1 for live DB-IP download")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "dbs")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ensureDBIP(dir, filepath.Join(root, "cache"), time.Now(), http.DefaultClient, dbipDownloadURL); err != nil {
		t.Fatal(err)
	}
	manifest, err := validateDBIP(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("verified live sources: %+v", manifest)
	original := resolvers.DataBaseFolderPath
	resolvers.DataBaseFolderPath = dir
	t.Cleanup(func() { resolvers.Init(resolvers.Config{}, true); resolvers.DataBaseFolderPath = original })
	if path := os.Getenv("NETCAP_GEOIP_GEOLITE_DIR"); path != "" {
		for _, file := range []string{"GeoLite2-City.mmdb", "GeoLite2-ASN.mmdb"} {
			if err := os.Symlink(filepath.Join(path, file), filepath.Join(dir, file)); err != nil {
				t.Fatal(err)
			}
		}
	}
	orders := []string{"dbip", "dbip,geolite2", "geolite2,dbip"}
	if os.Getenv("NETCAP_GEOIP_GEOLITE_DIR") != "" {
		orders = append(orders, "geolite2")
	}
	for _, order := range orders {
		resolvers.Init(resolvers.Config{GeolocationDB: true, GeoProviders: order}, true)
		location, asn := resolvers.LookupGeolocation("49.12.83.252")
		t.Logf("%s: %s; %s", order, location, asn)
		if location == "" || asn == "" {
			t.Fatalf("no result for %s", order)
		}
		if binary := os.Getenv("NETCAP_GEOIP_CAPTURE_BIN"); binary != "" {
			testGeoIPCapture(t, binary, root, order, location, asn)
		}
	}
	resolvers.Init(resolvers.Config{GeolocationDB: true, GeoProviders: "dbip"}, true)
	if binary := os.Getenv("NETCAP_GEOIP_CAPTURE_BIN"); binary != "" {
		missingRoot := t.TempDir()
		if err := os.Mkdir(filepath.Join(missingRoot, "dbs"), 0o755); err != nil {
			t.Fatal(err)
		}
		testGeoIPCapture(t, binary, missingRoot, "dbip,geolite2", "", "")
	}
	for _, ip := range []string{"4000::1", "3fff::1", "10.0.0.1"} {
		if loc, _ := resolvers.LookupGeolocation(ip); loc != "" {
			t.Fatalf("bogus %s: %s", ip, loc)
		}
	}
	archive := filepath.Join(root, "v2.tar.gz")
	sum, size, err := new(DBServer).createTarball(dir, archive)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySHA256(archive, sum); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	seen := map[string]bool{}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if excludedFromDistribution(h.Name) {
			t.Fatal("excluded data shipped", h.Name)
		}
		seen[h.Name] = true
	}
	for _, file := range []string{"dbip-city-lite.mmdb", "dbip-asn-lite.mmdb", "geoip-sources.json", "DATABASE_NOTICES.txt"} {
		if !seen[file] {
			t.Fatal("missing", file)
		}
	}
	t.Logf("local DB-IP archive: sha256=%s size=%d", sum, size)
}

func testGeoIPCapture(t *testing.T, binary, root, order, location, asn string) {
	t.Helper()
	pcap := filepath.Join(root, "geoip.pcap")
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("49.12.83.252"), DstIP: net.ParseIP("8.8.8.8")}
	udp := &layers.UDP{SrcPort: 40000, DstPort: 40001}
	udp.SetNetworkLayerForChecksum(ip)
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload("GeoIP fixture")); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(pcap)
	if err != nil {
		t.Fatal(err)
	}
	writer := pcapgo.NewWriter(f)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	if err := writer.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes())}, buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	f.Close()
	out := filepath.Join(root, "capture-"+strings.ReplaceAll(order, ",", "-"))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "capture", "-read", pcap, "-out", out, "-http", "", "-json", "-compress=false", "-dpi=false", "-macDB=false", "-serviceDB=false", "-workers", "1", "-geoProviders", order)
	cmd.Env = append(os.Environ(), "NC_CONFIG_ROOT="+root)
	if body, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("capture %s: %v\n%s", order, err, body)
	}
	files, err := filepath.Glob(filepath.Join(out, "*Connection*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		dec := json.NewDecoder(f)
		for {
			var record map[string]any
			err := dec.Decode(&record)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if record["SrcIP"] != "49.12.83.252" {
				continue
			}
			gotLocation, _ := record["SrcGeoLocation"].(string)
			gotASN, _ := record["SrcASN"].(string)
			if gotLocation != location || gotASN != asn {
				t.Fatalf("capture %s: (%v,%v), want (%s,%s)", order, record["SrcGeoLocation"], record["SrcASN"], location, asn)
			}
			t.Logf("capture %s: %s; %s", order, gotLocation, gotASN)
			return
		}
	}
	t.Fatalf("capture %s emitted no matching Connection JSON: %v", order, files)
}
