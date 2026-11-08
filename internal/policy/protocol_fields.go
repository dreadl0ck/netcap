package policy

import "reflect"

type NetworkEvent struct {
	SrcIP     string `json:"src_ip" yaml:"src_ip"`
	DstIP     string `json:"dst_ip" yaml:"dst_ip"`
	SrcPort   int    `json:"src_port" yaml:"src_port"`
	DstPort   int    `json:"dst_port" yaml:"dst_port"`
	Transport string `json:"transport" yaml:"transport"`
	IPVersion int    `json:"ip_version" yaml:"ip_version"`
	TCPFlags  int    `json:"tcp_flags" yaml:"tcp_flags"`
	Direction string `json:"direction" yaml:"direction"`
}

type TLSEvent struct {
	ServerName string `json:"server_name" yaml:"server_name"`
	ALPN       string `json:"alpn" yaml:"alpn"`
	JA4        string `json:"ja4" yaml:"ja4"`
	Encrypted  bool   `json:"encrypted" yaml:"encrypted"`
}

type FieldInfo struct{ Name, Type string }

// DiscoverFields returns expression names, including map element types. Dynamic
// keys are adapter-defined; missing map keys evaluate as the empty string.
func DiscoverFields() []FieldInfo {
	var result []FieldInfo
	var walk func(reflect.Type, string)
	walk = func(t reflect.Type, prefix string) {
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name := prefix + f.Name
			if f.Type.Kind() == reflect.Struct {
				walk(f.Type, name+".")
			} else {
				result = append(result, FieldInfo{name, f.Type.String()})
			}
		}
	}
	walk(reflect.TypeOf(Event{}), "")
	return result
}
