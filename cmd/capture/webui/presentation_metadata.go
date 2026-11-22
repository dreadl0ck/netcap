package webui

import "strings"

var configOptionLabels = map[string]string{
	"input": "Input file", "out": "Output directory", "compress": "Compression", "workers": "Workers", "pbuf": "Packet buffer", "membuf-size": "Memory buffer size",
	"bpf": "BPF filter", "iface": "Network interface", "promisc": "Promiscuous mode", "snaplen": "Snapshot length", "include": "Included decoders", "exclude": "Excluded decoders",
	"base": "Base layer", "opts": "Decoding options", "payload": "Payload capture", "context": "Packet context", "macDB": "MAC vendor database", "serviceDB": "Service database",
	"geoDB": "Geolocation database", "dpi": "Deep packet inspection", "reverse-dns": "Reverse DNS", "local-dns": "Local DNS", "reassemble-connections": "TCP connection reassembly",
	"flushevery": "Assembler flush interval", "checksum": "TCP checksums", "nooptcheck": "Skip TCP option checks", "ignorefsmerr": "Ignore TCP state errors", "allowmissinginit": "Allow missing handshake",
	"close-pending-timeout": "Pending connection timeout", "close-inactive-timeout": "Inactive connection timeout", "proto": "Protobuf output", "json": "JSON output", "csv": "CSV output",
	"elastic": "Elasticsearch output", "elastic-addrs": "Elasticsearch endpoints", "elastic-user": "Elasticsearch user", "debug": "Debug logging", "buf": "Output buffering",
	"ignore-unknown": "Skip unknown packets", "free-os-mem": "OS memory release interval", "conn-flush-interval": "Connection flush interval", "conn-timeout": "Connection timeout", "flow-flush-interval": "Flow flush interval", "flow-timeout": "Flow timeout",
}

func presentConfigOptions(options []ConfigOption, p Presentation) {
	for i := range options {
		o := &options[i]
		label := configOptionLabels[o.Name]
		if label == "" {
			label = o.Name
		}
		o.LabelI18n = p.message("config.option."+o.Name+".label", label, nil)
		o.DescriptionI18n = p.message("config.option."+o.Name+".description", o.Description, nil)
		o.CategoryI18n = p.message("config.category."+strings.ToLower(strings.NewReplacer("/", "-", " ", "-").Replace(o.Category)), o.Category, nil)
	}
}

func presentFeatures(features []FeatureState, p Presentation) []FeatureState {
	for i := range features {
		f := &features[i]
		f.TitleI18n = p.message("feature."+f.Name+".title", f.Title, nil)
		f.DescriptionI18n = p.message("feature."+f.Name+".description", f.Description, nil)
		scope := "Next API request"
		if f.Scope == featureScopeCapture {
			scope = "Next capture analysis"
		}
		f.ScopeI18n = p.message("feature.scope."+f.Scope, scope, nil)
	}
	return features
}

func presentChartFields(response *ChartFieldsResponse, p Presentation) {
	response.DiscoveryI18n = p.message("chart.fields.prefix_discovery", response.Discovery, map[string]any{"sampleLimit": response.SampleLimit})
	for i := range response.Fields {
		f := &response.Fields[i]
		f.TypeI18n = p.message("chart.field_type."+strings.NewReplacer(" ", "_", "(", "", ")", "").Replace(f.Type), f.Type, nil)
		id := "chart.field." + f.Name + ".description"
		params := map[string]any(nil)
		if _, ok := chartFieldDescriptions[f.Name]; !ok {
			// A discovered map key or custom field is evidence, not catalog text.
			id, params = "chart.field.description", map[string]any{"field": f.Name}
			f.DescriptionI18n = UIMessage{ID: id, Params: params, Text: f.Description}
			continue
		}
		f.DescriptionI18n = p.message(id, f.Description, params)
	}
}

func presentChartCoverage(coverage *ChartCoverage, p Presentation) {
	coverage.LimitationsI18n = make([]UIMessage, len(coverage.Limitations))
	for i, limitation := range coverage.Limitations {
		id := chartLimitationIDs[limitation]
		if id == "" {
			id = "chart.coverage.limitation"
		}
		coverage.LimitationsI18n[i] = p.message(id, limitation, nil)
	}
}

var chartLimitationIDs = map[string]string{
	"Only retained records with the requested numeric field contribute; absence is not zero traffic":    "chart.coverage.retained_numeric",
	"Values are sums of per-capture bucket means":                                                       "chart.coverage.summed_capture_means",
	"Min/max are record values; average is a bucket-count-weighted mean of per-capture record averages": "chart.coverage.statistics",
	"Values are per-bucket arithmetic means":                                                            "chart.coverage.bucket_means",
}
