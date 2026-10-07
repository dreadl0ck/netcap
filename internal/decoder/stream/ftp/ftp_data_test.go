package ftp

import (
	"bufio"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/file"
	"github.com/gopacket/gopacket"
)

func dataTestState(t *testing.T) {
	t.Helper()
	old := config.Instance
	config.Instance = &config.Config{FileStorage: "files"}
	oldFile := file.GetGlobalConfig()
	cfg := file.GetDefaultConfig()
	cfg.FileExtraction.Enabled = true
	cfg.FileExtraction.Protocols.FTP = true
	file.SetGlobalConfig(cfg)
	initConnectionTracker()
	t.Cleanup(func() {
		dataState.Lock()
		dataState.enabled = false
		dataState.bytes = 0
		dataState.streams = nil
		dataState.transfers = nil
		dataState.Unlock()
		config.Instance = old
		file.SetGlobalConfig(oldFile)
	})
}

func TestPendingDataBudgetsAndOwnership(t *testing.T) {
	dataTestState(t)
	fragment := &core.StreamData{RawData: []byte("owned"), CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(1, 0)}}
	c := &core.ConversationInfo{TCPHandshakeComplete: true, Data: core.DataFragments{fragment}}
	ObserveDataConversation(c)
	fragment.RawData[0] = 'X'
	if string(dataState.streams[0].data[0]) != "owned" {
		t.Fatal("pending bytes alias producer buffer")
	}
	for i := 1; i < maxPendingStreams+1; i++ {
		ObserveDataConversation(c)
	}
	if len(dataState.streams) != maxPendingStreams || dataState.health.Rejected != 1 {
		t.Fatal("stream count budget not enforced")
	}
	initConnectionTracker()
	fragment.RawData = make([]byte, maxPendingBytes+1)
	ObserveDataConversation(c)
	if dataState.bytes != 0 || len(dataState.streams) != 0 || dataState.health.Rejected != 1 || dataState.health.Status != "partial" {
		t.Fatal("oversized candidate retained or silently discarded")
	}
	for range maxPendingTransfers + 1 {
		registerTransfer(dataTransfer{Accepted: true, Passive: true, IP: "192.0.2.1", ServerIP: "192.0.2.1", Filename: "lab"})
	}
	if len(dataState.transfers) != maxPendingTransfers || dataState.health.Rejected != 2 {
		t.Fatal("control state budget not enforced")
	}
}

func TestPendingCorrelationArrivalOrder(t *testing.T) {
	for _, controlFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "data-first", true: "control-first"}[controlFirst], func(t *testing.T) {
			dataTestState(t)
			transfer := dataTransfer{Accepted: true, Passive: true, IP: "198.51.100.1", ServerIP: "198.51.100.1", ClientIP: "192.0.2.1", Port: 50000, Start: 1e9, End: 3e9}
			c := &core.ConversationInfo{TCPHandshakeComplete: true, ClientIP: transfer.ClientIP, ServerIP: transfer.ServerIP, ServerPort: 50000, Data: core.DataFragments{&core.StreamData{RawData: []byte("lab"), CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(2, 0)}}}}
			if controlFirst {
				registerTransfer(transfer)
				ObserveDataConversation(c)
			} else {
				ObserveDataConversation(c)
				registerTransfer(transfer)
			}
			if len(dataState.streams) != 1 || len(dataState.transfers) != 1 || !matchesTransfer(dataState.transfers[0], dataState.streams[0]) {
				t.Fatal("worker order changed association")
			}
			p := dataState.streams[0]
			p.conv.ClientIP = "192.0.2.2"
			if matchesTransfer(transfer, p) {
				t.Fatal("wrong peer matched")
			}
			p = dataState.streams[0]
			p.first = 0
			if matchesTransfer(transfer, p) {
				t.Fatal("stale payload matched")
			}
		})
	}
}

func TestFTPInvalidNegotiation(t *testing.T) {
	for _, s := range []string{"192,0,2,1,256,1", "999,0,2,1,1,1", "192,0,2,1,-1,1", "192,0,2,1,0,0", "192,0,2,1,1"} {
		if ip, port := parseEndpoint(s); ip != "" || port != 0 {
			t.Fatalf("invalid endpoint accepted: %s", s)
		}
	}
	f := &ftpReader{conversation: &core.ConversationInfo{ServerIP: "198.51.100.1"}}
	for _, s := range []string{"229 Passive ()\r\n", "229 Passive (||||)\r\n", "229 Passive (|||99999|)\r\n", "229 Passive (|x|y|50000|)\r\n"} {
		if err := f.readServer(bufio.NewReader(strings.NewReader(s)), nil); err != nil {
			t.Fatal(err)
		}
		if f.dataIP != "" || f.dataPort != 0 {
			t.Fatal("invalid EPSV endpoint accepted")
		}
	}
	if err := f.readServer(bufio.NewReader(strings.NewReader("229 Passive (|||50000|)\r\n")), nil); err != nil {
		t.Fatal(err)
	}
	if f.dataIP != "198.51.100.1" || f.dataPort != 50000 || !f.isPassive {
		t.Fatal("valid EPSV failed")
	}
	if err := f.readClient(bufio.NewReader(strings.NewReader("EPRT |2|2001:DB8::1|50000|\r\n")), nil); err != nil {
		t.Fatal(err)
	}
	if f.dataIP != "2001:db8::1" || f.dataPort != 50000 || f.isPassive {
		t.Fatal("valid EPRT failed")
	}
}
