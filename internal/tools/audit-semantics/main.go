// Command audit-semantics exports owned cross-language wire/export fixtures.
package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

func main() {
	const observed = int64(1590969600000000123)
	records := []types.AuditRecord{&types.HTTP{}, &types.DNS{}, &types.Kerberos{}, &types.TACACS{}, &types.IPP{}, &types.Zabbix{}, &types.Protobuf{}, &types.OPCUA{}, &types.S7Comm{}, &types.PROFINET{},
		&types.TLSCertificate{AssessmentTime: observed, AssessmentBasis: "capture-time", ValidityState: "valid", SelfSignatureState: "verified", CertificateSender: "client", NotBeforeRFC3339: "2020-01-01T00:00:00Z", NotAfterRFC3339: "9999-12-31T00:00:00Z"},
		&types.RDP{NegotiationOutcome: "accepted", AuthenticationOutcome: "unknown", NegotiatedSecurityKnown: true, UsesTLS: true, ConnectionSuccessful: true}}
	type fixture struct {
		Type   string          `json:"type"`
		Wire   string          `json:"wire"`
		JSON   json.RawMessage `json:"json"`
		Header []string        `json:"header"`
		Row    []string        `json:"row"`
	}
	var out []fixture
	for _, record := range records {
		v := reflect.ValueOf(record).Elem()
		v.FieldByName("Timestamp").SetInt(observed)
		v.FieldByName("CommunityID").SetString("1:LQU9qZlK+B5F3KDmev6m5PMibrg=")
		v.FieldByName("SrcIP").SetString("192.0.2.1")
		v.FieldByName("DstIP").SetString("198.51.100.1")
		b, err := proto.Marshal(record.(proto.Message))
		if err != nil {
			panic(err)
		}
		j, err := json.Marshal(record)
		if err != nil {
			panic(err)
		}
		out = append(out, fixture{record.NetcapType().String(), base64.StdEncoding.EncodeToString(b), j, record.CSVHeader(), record.CSVRecord()})
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(out); err != nil {
		panic(err)
	}
}
