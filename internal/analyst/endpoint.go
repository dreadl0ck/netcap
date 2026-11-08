package analyst

import (
	"fmt"
	"net/netip"
	"reflect"
	"strconv"
	"strings"

	"github.com/gogo/protobuf/proto"
)

var endpointPorts = map[string]map[string]string{
	"Connection": {"SrcIP": "SrcPort", "DstIP": "DstPort"}, "HTTP": {"SrcIP": "SrcPort", "DstIP": "DstPort"}, "DNS": {"SrcIP": "SrcPort", "DstIP": "DstPort"},
	"TLSClientHello": {"SrcIP": "SrcPort", "DstIP": "DstPort"}, "TLSCertificate": {"SrcIP": "SrcPort", "DstIP": "DstPort"}, "Service": {"IP": "Port"},
}

func parseEndpoint(value string) (netip.Addr, uint16, bool, string, error) {
	protocol := ""
	if prefix, rest, ok := strings.Cut(value, "://"); ok {
		protocol = strings.ToUpper(prefix)
		if protocol != "TCP" && protocol != "UDP" {
			return netip.Addr{}, 0, false, "", fmt.Errorf("endpoint transport must be tcp or udp")
		}
		value = rest
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Unmap(), 0, false, protocol, nil
	}
	socket, err := netip.ParseAddrPort(value)
	if err != nil || socket.Port() == 0 {
		return netip.Addr{}, 0, false, "", fmt.Errorf("endpoint requires an exact IP or IP:nonzero-port")
	}
	return socket.Addr().Unmap(), socket.Port(), true, protocol, nil
}
func endpointPort(msg proto.Message, field string) (uint16, bool) {
	if field == "" {
		return 0, false
	}
	v := reflect.ValueOf(msg)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return 0, false
	}
	v = v.FieldByName(field)
	if !v.IsValid() {
		return 0, false
	}
	text := ""
	switch v.Kind() {
	case reflect.String:
		text = v.String()
	case reflect.Int, reflect.Int32, reflect.Int64:
		text = strconv.FormatInt(v.Int(), 10)
	case reflect.Uint, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		text = strconv.FormatUint(v.Uint(), 10)
	default:
		return 0, false
	}
	port, err := strconv.ParseUint(text, 10, 16)
	return uint16(port), err == nil && port != 0
}
func matchEndpoint(q Query, msg proto.Message, typ string) []string {
	want, port, socket, transport, err := parseEndpoint(q.Value)
	if err != nil {
		return nil
	}
	if transport != "" {
		observed := scalarValues(reflect.ValueOf(msg), []string{"TransportProto"})
		if len(observed) != 1 || !strings.EqualFold(observed[0], transport) {
			return nil
		}
	}
	fields := []string{}
	for _, field := range catalogueFields[typ]["endpoint"] {
		for _, value := range scalarValues(reflect.ValueOf(msg), []string{field}) {
			address, err := netip.ParseAddr(value)
			if err != nil || address.Unmap() != want {
				continue
			}
			if socket {
				actual, ok := endpointPort(msg, endpointPorts[typ][field])
				if !ok || actual != port {
					continue
				}
				fields = append(fields, field+"+"+endpointPorts[typ][field])
			} else {
				fields = append(fields, field)
			}
			break
		}
	}
	return fields
}
func endpointAvailable(q Query, msg proto.Message, typ string) bool {
	_, _, socket, transport, err := parseEndpoint(q.Value)
	if err != nil {
		return false
	}
	if transport != "" {
		observed := scalarValues(reflect.ValueOf(msg), []string{"TransportProto"})
		if len(observed) != 1 || observed[0] == "" {
			return false
		}
	}
	for _, field := range catalogueFields[typ][q.Kind] {
		values := scalarValues(reflect.ValueOf(msg), []string{field})
		if len(values) != 1 {
			return false
		}
		if _, err := netip.ParseAddr(values[0]); err != nil {
			return false
		}
		if socket {
			if _, ok := endpointPort(msg, endpointPorts[typ][field]); !ok {
				return false
			}
		}
	}
	return true
}
