package service

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/software"
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/internal/servicesignatures"
	"github.com/dreadl0ck/netcap/types"
	"go.uber.org/zap"
)

var (
	signatureEngine        atomic.Pointer[servicesignatures.Engine]
	signatureInventory     atomic.Pointer[servicesignatures.Inventory]
	signatureWarningWriter io.Writer = os.Stderr
)

func init() {
	if decoderconfig.Instance == nil {
		decoderconfig.Instance = decoderconfig.DefaultConfig
	}
	serviceLog = zap.NewNop()
	signatureEngine.Store(servicesignatures.Builtin())
}

// ResetProbeEnums remains for callers resetting capture state. IDs are now stable.
func ResetProbeEnums() {}

func initServiceProbes() error {
	e, err := servicesignatures.Load(filepath.Join(resolvers.DataBaseFolderPath, servicesignatures.FileName))
	signatureEngine.Store(e)
	inventory := e.Inventory("capture", err)
	signatureInventory.Store(&inventory)
	if err != nil {
		serviceLog.Warn("service signature coverage degraded", zap.Error(err))
		fmt.Fprintln(signatureWarningWriter, err)
	}
	return nil
}

// SignatureInventory is the actual decoder initialization result, not a re-read
// of a catalogue that may have changed since the capture started.
func SignatureInventory() servicesignatures.Inventory {
	i := signatureInventory.Load()
	if i == nil {
		return servicesignatures.UnavailableInventory("not-initialized", "Service decoder has not initialized a catalogue")
	}
	return *i
}

func MatchServiceProbes(serv *service, banner []byte, ident string) {
	r, ok := signatureEngine.Load().Identify(banner, strings.ToLower(serv.Protocol), "server-to-client")
	if !ok {
		return
	}
	serv.Name = r.Protocol
	serv.MatchedProbeID = r.ID
	serv.Product, serv.Version = r.Product, r.Version
	if r.Protocol == "http" {
		matchHTTPHeaders(serv, banner, ident)
	}
	if serv.Product != "" && r.Protocol != "http" {
		writeSoftwareFromBanner(serv, ident, r.ID)
	}
}

func writeSoftwareFromBanner(serv *service, ident, probeIdent string) {
	software.WriteSoftware([]*software.AtomicSoftware{{Software: &types.Software{
		ObservedHost: serv.IP, ObservationRole: "server",
		Timestamp: serv.Timestamp, Product: serv.Product, Vendor: serv.Vendor, Version: serv.Version,
		SourceName: "Service Signature: " + probeIdent, Service: serv.Name, Flows: []string{ident}, Notes: "Protocol: " + serv.Protocol,
	}}}, nil)
}

func matchHTTPHeaders(serv *service, banner []byte, ident string) {
	if len(banner) > servicesignatures.MaxBannerBytes {
		banner = banner[:servicesignatures.MaxBannerBytes]
	}
	if !strings.HasPrefix(string(banner), "HTTP/1.") {
		return
	}
	h, v := extractHeaderManually(string(banner), []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator", "Via", "X-Cache"})
	if v != "" {
		parseHeaderValue(serv, h, v, ident)
	}
}

func extractHeaderManually(banner string, priorityHeaders []string) (string, string) {
	lines := strings.Split(banner, "\n")
	for _, target := range priorityHeaders {
		for _, line := range lines[1:] {
			line = strings.TrimSuffix(line, "\r")
			if line == "" {
				break
			}
			name, value, ok := strings.Cut(line, ":")
			if ok && strings.EqualFold(name, target) && strings.TrimSpace(value) != "" {
				return target, strings.TrimSpace(value)
			}
		}
	}
	return "", ""
}

func parseHeaderValue(serv *service, name, value, ident string) {
	var p, v string
	value = strings.TrimSpace(value)
	switch name {
	case "Server":
		p, v = parseServerHeader(value)
	case "X-Powered-By":
		p, v = parseXPoweredByHeader(value)
	case "X-AspNet-Version":
		p, v = "ASP.NET", value
	case "X-AspNetMvc-Version":
		p, v = "ASP.NET MVC", value
	case "X-Generator":
		p, v = parseGeneratorHeader(value)
	case "Via":
		p, v = parseViaHeader(value)
	case "X-Cache":
		p = "CDN/Cache: " + value
	}
	if p != "" {
		serv.Product = addInfo(serv.Product, p)
		serv.Version = addInfo(serv.Version, v)
		if serv.MatchedProbeID == "" {
			serv.MatchedProbeID = "netcap.http.response.v1"
		}
		writeSoftwareFromBanner(serv, ident, serv.MatchedProbeID)
	}
}

func parseServerHeader(value string) (string, string) {
	p := strings.Fields(value)
	if len(p) == 0 {
		return "", ""
	}
	return parseXPoweredByHeader(p[0])
}
func parseXPoweredByHeader(value string) (string, string) {
	p, v, _ := strings.Cut(value, "/")
	return p, v
}
func parseGeneratorHeader(value string) (string, string) {
	p := strings.Fields(value)
	if len(p) == 0 {
		return "", ""
	}
	if len(p) == 1 {
		return p[0], ""
	}
	return p[0], strings.TrimPrefix(p[1], "v")
}
func parseViaHeader(value string) (string, string) {
	p := strings.Fields(value)
	if len(p) < 2 {
		return "Proxy", ""
	}
	return parseXPoweredByHeader(p[1])
}
