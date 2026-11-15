package webui

import (
	"os"
	"sort"
	"strconv"
	"strings"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
)

type protobufSettings struct {
	Paths, Mappings []string
	Alternatives    bool
}

func currentProtobufSettings() protobufSettings {
	protoRuntime.mu.RLock()
	defer protoRuntime.mu.RUnlock()
	var v protobufSettings
	decoderconfig.LockInstance()
	if decoderconfig.Instance != nil {
		v = protobufSettings{append([]string{}, decoderconfig.Instance.ProtoSearchPaths...), append([]string{}, decoderconfig.Instance.ProtoMessageTypes...), decoderconfig.Instance.ProtoShowAlternatives}
	}
	decoderconfig.UnlockInstance()
	if protoRuntime.searchPaths != nil {
		v.Paths = append([]string{}, protoRuntime.searchPaths...)
	}
	if protoRuntime.mappings != nil {
		v.Mappings = append([]string{}, protoRuntime.mappings...)
	}
	if protoRuntime.alternatives != nil {
		v.Alternatives = *protoRuntime.alternatives
	}
	return v
}

// Explicit flags override inherited NC_* values, including false/empty settings.
func (snapshot *jobSettings) helperArgs() []string {
	rc, dpiEnabled, payloadEnabled := snapshot.Runtime, snapshot.DPI, snapshot.Payload
	values := map[string]string{
		"dpi": strconv.FormatBool(dpiEnabled), "dpi-modules": rc.DPIModules, "payload": strconv.FormatBool(payloadEnabled),
		"capture-evidence": strconv.FormatBool(rc.CaptureEvidence), "flow-exports": strconv.FormatBool(rc.FlowExports),
		"retain-packets": strconv.FormatBool(rc.RetainPackets), "packet-segment-mb": strconv.FormatInt(rc.PacketSegmentBytes>>20, 10), "packet-retention-mb": strconv.FormatInt(rc.PacketRetentionBytes>>20, 10),
		"max-retained-tcp-bytes": strconv.FormatInt(rc.MaxRetainedTCPBytes, 10), "max-retained-reassembly-bytes": strconv.FormatInt(rc.MaxRetainedReassemblyBytes, 10),
		"max-retained-tcp-state-bytes": strconv.FormatInt(rc.MaxRetainedTCPStateBytes, 10), "max-aggregate-state-bytes": strconv.FormatInt(rc.MaxAggregateStateBytes, 10),
		"incremental-http": strconv.FormatBool(rc.IncrementalHTTP), "capture-time-idle-expiry": strconv.FormatBool(rc.CaptureTimeIdleExpiry),
		"modbus-rtu-endpoints": rc.ModbusRTUEndpoints, "dnp3-point-map": rc.DNP3PointMap, "flow-export-ports": rc.FlowExportPorts,
		"network-detection": strconv.FormatBool(snapshot.NetworkDetection), "dns-resolution-context": strconv.FormatBool(snapshot.DNSContext),
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	args := []string{}
	for _, k := range keys {
		args = append(args, "-"+k+"="+values[k])
	}
	proto := snapshot.Protobuf
	args = append(args, "-proto-show-alternatives="+strconv.FormatBool(proto.Alternatives))
	// The CLI splits on commas without quote processing; snapshot roots are safe.
	for _, item := range []struct {
		name   string
		values []string
	}{{"proto-paths", proto.Paths}, {"proto-message-types", proto.Mappings}} {
		for _, value := range item.values {
			args = append(args, "-"+item.name+"="+value)
		}
	}
	return args
}

func helperEnvironment() []string {
	result := []string{}
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		if key == "NC_PROTO_PATHS" || key == "NC_PROTO_MESSAGE_TYPES" || key == "NC_PROTO_SHOW_ALTERNATIVES" {
			continue
		}
		result = append(result, item)
	}
	return result
}
