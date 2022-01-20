package tcp_test

import (
	"fmt"
	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/collector"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/felixge/fgprof"
	"log"
	"net/http"
	"os"
	"runtime/pprof"
	"testing"
)

// essentially:
// net capture -read http-reassembly-test.pcap -workers 1
func TestReassembleStreamFromPCAP(t *testing.T) {

	var profile = false

	// configure CPU profiling
	if profile {
		defer func() func() {
			if profile {
				f, errCPUProfile := os.Create("netcap-" + netcap.Version + ".cpu.profile")
				if errCPUProfile != nil {
					log.Fatalf("could not open cpu profile file %q, error: %s\n", "netcap.cpu.profile", errCPUProfile)
				}

				if errCPUProfile = pprof.StartCPUProfile(f); errCPUProfile != nil {
					log.Fatalf("failed to start CPU profiling, error: %s\n", errCPUProfile)
				}

				return func() {
					pprof.StopCPUProfile()

					errCPUProfile = f.Close()
					if errCPUProfile != nil {
						panic("failed to write CPU profile: " + errCPUProfile.Error())
					}
				}
			}

			return func() {}
		}()

		// fgprof allows to analyze On-CPU as well as Off-CPU (e.g. I/O) time
		http.DefaultServeMux.Handle("/debug/fgprof", fgprof.Handler())

		go func() {
			log.Println(http.ListenAndServe(":6060", nil))
		}()
	}

	// set data source
	var source = "../../../pcaps/http-reassembly-test.pcap"

	reassembly.Debug = false

	// configure
	collector.DefaultConfig.Workers = 1
	collector.DefaultConfig.DecoderConfig.Out = "http-reassembly-test"
	collector.DefaultConfig.DecoderConfig.SaveConns = true
	collector.DefaultConfig.ReassembleConnections = true
	collector.DefaultConfig.NoPrompt = true

	// init collector
	c := collector.New(collector.DefaultConfig)
	c.InputFile = source

	c.PrintConfiguration()

	// if not, use native pcapgo version
	isPcap, err := collector.IsPcap(source)
	if err != nil {
		// invalid path
		fmt.Println("failed to open file:", err)
		os.Exit(1)
	}

	if isPcap {
		if err = c.CollectPcap(source); err != nil {
			log.Fatal("failed to collect audit records from pcap file: ", err)
		}
	} else {
		if err = c.CollectPcapNG(source); err != nil {
			log.Fatal("failed to collect audit records from pcapng file: ", err)
		}
	}

	// memory profiling
	if profile {
		f, errProfile := os.Create("netcap-" + netcap.Version + ".mem.profile")
		if errProfile != nil {
			log.Fatal("failed create memory profile: ", errProfile)
		}

		if errProfile = pprof.WriteHeapProfile(f); errProfile != nil {
			log.Fatal("failed to write heap profile: ", errProfile)
		}

		err = f.Close()
		if err != nil {
			panic("failed to write memory profile: " + err.Error())
		}
	}

	s, err := os.Stat("http-reassembly-test/tcp/world-wide-web-http/192.168.0.54-49412--80.239.217.161-80.bin")
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("tcp stream data size", s.Size())
	if s.Size() != 4692481 {
		t.Fatal("expected 4692481 bytes")
	}
}
