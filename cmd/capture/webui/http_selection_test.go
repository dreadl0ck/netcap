package webui

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func observedTuplePCAP(t *testing.T) (string, time.Time) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "owned.pcap")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := pcapgo.NewWriterNanos(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1700000000, 0)
	for index, candidate := range []struct {
		src, dst string
		sp, dp   uint16
		udp      bool
	}{
		{"192.0.2.1", "198.51.100.1", 52123, 9243, false},
		{"192.0.2.1", "198.51.100.1", 52123, 9243, false},
		{"198.51.100.1", "192.0.2.1", 9243, 52123, false},
		{"192.0.2.1", "198.51.100.1", 52124, 9243, false},
		{"192.0.2.1", "198.51.100.1", 9243, 52123, false},
		{"192.0.2.1", "198.51.100.1", 52123, 9243, true},
	} {
		eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.ParseIP(candidate.src), DstIP: net.ParseIP(candidate.dst), Protocol: layers.IPProtocolTCP}
		var transport gopacket.SerializableLayer
		if candidate.udp {
			ip.Protocol = layers.IPProtocolUDP
			udp := &layers.UDP{SrcPort: layers.UDPPort(candidate.sp), DstPort: layers.UDPPort(candidate.dp)}
			if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
				t.Fatal(err)
			}
			transport = udp
		} else {
			tcp := &layers.TCP{SrcPort: layers.TCPPort(candidate.sp), DstPort: layers.TCPPort(candidate.dp), SYN: true}
			if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
				t.Fatal(err)
			}
			transport = tcp
		}
		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, transport); err != nil {
			t.Fatal(err)
		}
		if err := writer.WritePacket(gopacket.CaptureInfo{Timestamp: base.Add(time.Duration(min(index, 2))), CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes())}, buf.Bytes()); err != nil {
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path, base
}

func TestPacketDownloadsPreserveBinaryHTTPFraming(t *testing.T) {
	input, _ := observedTuplePCAP(t)
	s := &Server{activeInputFile: input, localAccessToken: "synthetic-download-token"}
	mux := http.NewServeMux()
	for path, handler := range map[string]http.HandlerFunc{
		"/api/http/download-pcap":         s.handleHTTPDownloadPCAP,
		"/api/certificates/download-pcap": s.handleCertificateDownloadPCAP,
		"/api/connections/download-pcap":  s.handleConnectionDownloadPCAP,
		"/api/hosts/download-pcap":        s.handleHostDownloadPCAP,
	} {
		mux.HandleFunc(path, handler)
	}
	ts := httptest.NewUnstartedServer(s.localSecurityMiddleware(gzipMiddleware(s.corsMiddleware(s.captureSelectionMiddleware(chartCoverageMiddleware(mux))))))
	s.addr = ts.Listener.Addr().String()
	ts.Start()
	defer ts.Close()
	query := url.Values{"srcIP": {"192.0.2.1"}, "dstIP": {"198.51.100.1"}, "srcPort": {"52123"}, "dstPort": {"9243"}, "protocol": {"TCP"}, "host": {"192.0.2.1"}}
	for _, path := range []string{"/api/http/download-pcap", "/api/certificates/download-pcap", "/api/connections/download-pcap", "/api/hosts/download-pcap"} {
		t.Run(path, func(t *testing.T) {
			var expected []byte
			for _, encoding := range []string{"identity", "", "gzip"} {
				req, err := http.NewRequest(http.MethodGet, ts.URL+path+"?"+query.Encode(), nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Authorization", "Bearer "+s.localAccessToken)
				if encoding != "" {
					req.Header.Set("Accept-Encoding", encoding)
				}
				resp, err := ts.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil || resp.StatusCode != 200 {
					t.Fatalf("encoding=%q: %d %v %s", encoding, resp.StatusCode, err, data)
				}
				if resp.Header.Get("Content-Encoding") != "" {
					t.Fatal("binary capture was recompressed")
				}
				if length := resp.Header.Get("Content-Length"); length != strconv.Itoa(len(data)) {
					t.Fatalf("framing length=%s actual=%d", length, len(data))
				}
				if expected == nil {
					expected = data
				} else if !bytes.Equal(data, expected) {
					t.Fatal("capture bytes changed with Accept-Encoding")
				}
				reader, err := pcapgo.NewReader(bytes.NewReader(data))
				if err != nil {
					t.Fatal(err)
				}
				count := 0
				for {
					_, _, err := reader.ReadPacketData()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
					count++
				}
				if count == 0 {
					t.Fatal("empty binary download control")
				}
			}
			for _, tc := range []struct {
				limit  string
				status int
			}{
				{strconv.Itoa(len(expected)), http.StatusOK},
				{strconv.Itoa(len(expected) - 1), http.StatusRequestEntityTooLarge},
				{"0", http.StatusBadRequest},
			} {
				req, err := http.NewRequest(http.MethodGet, ts.URL+path+"?"+query.Encode()+"&maxOutputBytes="+tc.limit, nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Authorization", "Bearer "+s.localAccessToken)
				resp, err := ts.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil || resp.StatusCode != tc.status {
					t.Fatalf("limit=%s: status=%d want=%d err=%v", tc.limit, resp.StatusCode, tc.status, err)
				}
				if tc.status == http.StatusOK && !bytes.Equal(data, expected) || tc.status != http.StatusOK && resp.Header.Get("Content-Disposition") != "" {
					t.Fatalf("unexpected artifact for limit=%s status=%d", tc.limit, tc.status)
				}
			}
		})
	}
}

func TestPacketDownloadsShareSlotsThroughResponseWrite(t *testing.T) {
	input, _ := observedTuplePCAP(t)
	s := &Server{activeInputFile: input}
	request := func() *http.Request {
		return httptest.NewRequest(http.MethodGet, "/download-pcap?host=192.0.2.1&srcIP=192.0.2.1&dstIP=198.51.100.1&srcPort=52123&dstPort=9243&protocol=TCP", nil)
	}
	baseline := httptest.NewRecorder()
	s.handleHostDownloadPCAP(baseline, request())
	if baseline.Code != http.StatusOK {
		t.Fatalf("baseline status=%d", baseline.Code)
	}
	release := make(chan struct{})
	done := make(chan *httptest.ResponseRecorder, 2)
	t.Cleanup(func() {
		if release != nil {
			close(release)
		}
	})
	for range 2 {
		held := heldAlertPageResponse{httptest.NewRecorder(), make(chan struct{}, 1), release}
		go func() {
			s.handleHostDownloadPCAP(held, request())
			done <- held.ResponseRecorder
		}()
		select {
		case <-held.writing:
		case <-time.After(5 * time.Second):
			t.Fatal("host download did not reach response writing")
		}
	}
	for _, handler := range []http.HandlerFunc{s.handleHTTPDownloadPCAP, s.handleCertificateDownloadPCAP, s.handleConnectionDownloadPCAP} {
		w := httptest.NewRecorder()
		handler(w, request())
		if w.Code != http.StatusTooManyRequests || w.Header().Get("Content-Disposition") != "" {
			t.Fatalf("saturated download: status=%d body=%q", w.Code, w.Body)
		}
	}
	close(release)
	release = nil
	for range 2 {
		select {
		case w := <-done:
			if w.Code != http.StatusOK || !bytes.Equal(baseline.Body.Bytes(), w.Body.Bytes()) {
				t.Fatalf("concurrent host download changed: status=%d bytes=%d", w.Code, w.Body.Len())
			}
		case <-time.After(5 * time.Second):
			t.Fatal("host download did not finish")
		}
	}
	retry := httptest.NewRecorder()
	s.handleHTTPDownloadPCAP(retry, request())
	if retry.Code != http.StatusOK {
		t.Fatalf("retry status=%d body=%q", retry.Code, retry.Body)
	}
}

func TestConnectionEvidenceArchiveOutputLimit(t *testing.T) {
	input, _ := observedTuplePCAP(t)
	s := &Server{activeInputFile: input}
	download := func(suffix string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleConnectionDownloadPCAP(w, httptest.NewRequest(http.MethodGet,
			"/download-pcap?format=evidence&srcIP=192.0.2.1&dstIP=198.51.100.1&srcPort=52123&dstPort=9243&protocol=TCP"+suffix, nil))
		return w
	}
	baseline := download("")
	if baseline.Code != http.StatusOK || baseline.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("baseline status=%d body=%q", baseline.Code, baseline.Body)
	}
	limit := baseline.Body.Len()
	exact := download("&maxOutputBytes=" + strconv.Itoa(limit))
	if exact.Code != http.StatusOK || !bytes.Equal(exact.Body.Bytes(), baseline.Body.Bytes()) {
		t.Fatalf("exact limit %d: status=%d size=%d", limit, exact.Code, exact.Body.Len())
	}
	for _, tc := range []struct{ limit, status int }{{limit - 1, 413}, {1, 413}, {0, 400}} {
		w := download("&maxOutputBytes=" + strconv.Itoa(tc.limit))
		if w.Code != tc.status || w.Header().Get("Content-Disposition") != "" {
			t.Fatalf("limit=%d: status=%d attachment=%q", tc.limit, w.Code, w.Header().Get("Content-Disposition"))
		}
	}
}

func TestHTTPPacketExportUsesObservedTupleTransportAndTime(t *testing.T) {
	path, base := observedTuplePCAP(t)
	s := &Server{activeInputFile: path}
	query := url.Values{"srcIP": {"192.0.2.1"}, "dstIP": {"198.51.100.1"}, "srcPort": {"52123"}, "dstPort": {"9243"}, "startNs": {"1700000000000000001"}, "endNs": {"1700000000000000002"}}
	for name, handler := range map[string]http.HandlerFunc{"HTTP": s.handleHTTPDownloadPCAP, "certificate": s.handleCertificateDownloadPCAP} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler(response, httptest.NewRequest("GET", "/download-pcap?"+query.Encode(), nil))
			if response.Code != 200 {
				t.Fatalf("%d: %s", response.Code, response.Body.String())
			}
			reader, err := pcapgo.NewReader(bytes.NewReader(response.Body.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for {
				_, info, err := reader.ReadPacketData()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				count++
				if !info.Timestamp.Equal(base.Add(time.Duration(count))) {
					t.Fatalf("wrong capture time: %v", info.Timestamp)
				}
			}
			if count != 2 {
				t.Fatalf("matched %d packets, want request and reverse response only", count)
			}
			for field, value := range map[string]string{"srcPort": "", "srcIP": "192.0.2.1 or host 203.0.113.1", "protocol": "UDP", "endNs": "invalid"} {
				invalid, _ := url.ParseQuery(query.Encode())
				invalid.Set(field, value)
				response := httptest.NewRecorder()
				handler(response, httptest.NewRequest("GET", "/download-pcap?"+invalid.Encode(), nil))
				if response.Code != 400 {
					t.Fatalf("accepted %s=%q: %d", field, value, response.Code)
				}
			}
		})
	}
}
