package analyst

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/gogo/protobuf/proto"
)

type Source struct {
	ID        string  `json:"id"`
	Binding   Binding `json:"binding"`
	Directory string  `json:"-"`
}
type Query struct {
	Kind  string   `json:"kind"`
	Value string   `json:"value"`
	Types []string `json:"types"`
}
type Occurrence struct {
	SourceID  string    `json:"sourceId"`
	Reference Reference `json:"reference"`
	Fields    []string  `json:"fields"`
	Endpoints []string  `json:"endpoints"`
}
type Coverage struct {
	FileSHA256         string  `json:"fileSHA256,omitempty"`
	SourceID           string  `json:"sourceId"`
	Binding            Binding `json:"binding"`
	Type               string  `json:"type"`
	State              string  `json:"state"`
	Records            int     `json:"records"`
	QualifiedRecords   int     `json:"qualifiedRecords"`
	UnqualifiedRecords int     `json:"unqualifiedRecords"`
}
type Catalogue struct {
	SnapshotSHA256   string       `json:"snapshotSHA256,omitempty"`
	TotalOccurrences int          `json:"totalOccurrences"`
	NextOffset       *int         `json:"nextOffset,omitempty"`
	Version          int          `json:"version"`
	Query            Query        `json:"query"`
	Sources          []Source     `json:"sources"`
	Coverage         []Coverage   `json:"coverage"`
	Occurrences      []Occurrence `json:"occurrences"`
	Novelty          string       `json:"novelty"`
	Limitations      []string     `json:"limitations"`
}

var catalogueFields = map[string]map[string][]string{
	"File":           {"sha256": {"Hashes.SHA256"}, "text": {"Name", "ContentType", "Protocol"}},
	"DNS":            {"domain": {"Questions.Name", "Answers.Name", "Answers.CNAME"}, "endpoint": {"SrcIP", "DstIP"}, "text": {"Questions.Name", "Answers.Name"}},
	"HTTP":           {"domain": {"Host"}, "endpoint": {"SrcIP", "DstIP"}, "text": {"Host", "URL", "UserAgent", "ServerName"}},
	"Connection":     {"endpoint": {"SrcIP", "DstIP"}, "text": {"ServerPortName", "ApplicationProto", "Applications", "TransportProto"}},
	"Software":       {"endpoint": {"ObservedHost"}, "text": {"Product", "Vendor", "Version", "OS", "SourceName"}},
	"TLSClientHello": {"domain": {"SNI"}, "endpoint": {"SrcIP", "DstIP"}, "text": {"SNI"}},
	"TLSCertificate": {"sha256": {"SHA256Fingerprint"}, "domain": {"SubjectCommonName", "SubjectAltNames"}, "endpoint": {"SrcIP", "DstIP"}, "text": {"SubjectCommonName", "IssuerCommonName"}},
	"Service":        {"endpoint": {"IP"}, "text": {"Product", "Vendor", "Version", "Name"}},
}

func ValidateQuery(q Query) error {
	if len(q.Value) == 0 || len(q.Value) > 512 || len(q.Types) == 0 || len(q.Types) > 8 {
		return fmt.Errorf("query requires 1–8 explicit types and 1–512 value bytes")
	}
	switch q.Kind {
	case "sha256":
		if !IsHash(q.Value) {
			return fmt.Errorf("SHA256 requires lowercase hex")
		}
	case "endpoint":
		if _, _, _, _, err := parseEndpoint(q.Value); err != nil {
			return err
		}
	case "domain", "text":
	default:
		return fmt.Errorf("unsupported catalogue kind")
	}
	seen := map[string]bool{}
	for _, typ := range q.Types {
		if seen[typ] || len(catalogueFields[typ][q.Kind]) == 0 {
			return fmt.Errorf("unsupported or duplicate type/kind: %s/%s", typ, q.Kind)
		}
		seen[typ] = true
		if q.Kind == "endpoint" {
			_, _, socket, transport, _ := parseEndpoint(q.Value)
			if socket && len(endpointPorts[typ]) == 0 {
				return fmt.Errorf("socket evidence unavailable for %s", typ)
			}
			if transport != "" && typ != "Connection" {
				return fmt.Errorf("explicit transport evidence is available only for Connection")
			}
		}
	}
	return nil
}

func scalarValues(v reflect.Value, parts []string) []string {
	if !v.IsValid() {
		return nil
	}
	for v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}
	if v.Kind() == reflect.Slice {
		if len(parts) == 0 && v.Type().Elem().Kind() == reflect.Uint8 {
			return []string{string(v.Bytes())}
		}
		var out []string
		for i := 0; i < v.Len(); i++ {
			out = append(out, scalarValues(v.Index(i), parts)...)
		}
		return out
	}
	if len(parts) == 0 {
		if v.Kind() == reflect.String {
			return []string{v.String()}
		}
		return nil
	}
	if v.Kind() != reflect.Struct {
		return nil
	}
	return scalarValues(v.FieldByName(parts[0]), parts[1:])
}

func Match(q Query, msg proto.Message, typ string) []string {
	if q.Kind == "endpoint" {
		return matchEndpoint(q, msg, typ)
	}
	var fields []string
	for _, field := range catalogueFields[typ][q.Kind] {
		for _, value := range scalarValues(reflect.ValueOf(msg), strings.Split(field, ".")) {
			if value == "" {
				continue
			}
			match := false
			switch q.Kind {
			case "sha256":
				match = strings.EqualFold(value, q.Value)
			case "domain":
				match = strings.EqualFold(strings.TrimSuffix(value, "."), strings.TrimSuffix(q.Value, "."))
			case "text":
				match = strings.Contains(value, q.Value)
			}
			if match {
				fields = append(fields, field)
				break
			}
		}
	}
	return fields
}

func criterionAvailable(q Query, msg proto.Message, typ string) bool {
	if q.Kind == "endpoint" {
		return endpointAvailable(q, msg, typ)
	}
	available := false
	for _, field := range catalogueFields[typ][q.Kind] {
		values := scalarValues(reflect.ValueOf(msg), strings.Split(field, "."))
		valid := false
		for _, value := range values {
			if value == "" {
				continue
			}
			if q.Kind == "sha256" {
				valid = IsHash(strings.ToLower(value))
			} else {
				valid = true
			}
			if valid {
				break
			}
		}
		available = available || valid
	}
	return available
}

// Search performs a finite scan of the explicitly supplied sources. Source zero
// is the target; later sources are the declared novelty baseline, never an estate.
func Search(ctx context.Context, sources []Source, q Query) (Catalogue, error) {
	result := Catalogue{Version: 1, Query: q, Sources: sources, Coverage: []Coverage{}, Occurrences: []Occurrence{}, Novelty: "unknown", Limitations: []string{
		"Catalogue covers only the explicitly included finalized captures and record types, not the estate or original omitted traffic",
		"Novelty compares source zero with the included baseline only; absent audit types make novelty unknown",
		"Records without usable selected indicator fields make novelty unknown; endpoint coverage requires every declared endpoint field",
		"Text is case-sensitive substring search of allowlisted metadata fields; domains are case-insensitive exact names without a terminal dot; endpoint IP is not account/host ownership",
		"Socket queries pair IP and observed port; tcp:// or udp:// requires explicit Connection transport. Port zero and inferred transports are unsupported",
		"Parent/child or overlapping captures may contain the same traffic; retained occurrences are not independent network events",
		"Artifact hashes describe retained bytes; resolve each File occurrence for transfer completeness and original context",
	}}
	if err := ValidateQuery(q); err != nil {
		return result, err
	}
	if len(sources) < 1 || len(sources) > 8 {
		return result, fmt.Errorf("include 1–8 explicit sources")
	}
	seen := map[string]bool{}
	target, baseline := false, false
	missing := false
	total := 0
	for i, source := range sources {
		if source.ID == "" || seen[source.ID] || seen["run:"+source.Binding.RunID] {
			return result, fmt.Errorf("duplicate or missing source identity")
		}
		seen[source.ID] = true
		seen["run:"+source.Binding.RunID] = true
		if err := Check(ctx, source.Directory, source.Binding); err != nil {
			return result, err
		}
		for _, typ := range q.Types {
			coverage := Coverage{SourceID: source.ID, Binding: source.Binding, Type: typ, State: "complete"}
			fileHash, err := Scan(ctx, source.Directory, source.Binding, typ, func(ref Reference, msg proto.Message) error {
				coverage.Records++
				if criterionAvailable(q, msg, typ) {
					coverage.QualifiedRecords++
				} else {
					coverage.UnqualifiedRecords++
					coverage.State = "partial-fields"
					missing = true
				}
				total++
				if total > MaxRecords {
					return fmt.Errorf("catalogue total record limit exceeded")
				}
				fields := Match(q, msg, typ)
				if len(fields) == 0 {
					return nil
				}
				if len(result.Occurrences) >= 4096 {
					return fmt.Errorf("catalogue occurrence limit exceeded; narrow the scope")
				}
				endpoints := []string{}
				for _, field := range []string{"SrcIP", "DstIP", "ObservedHost", "IP"} {
					for _, value := range scalarValues(reflect.ValueOf(msg), []string{field}) {
						if _, err := netip.ParseAddr(value); err == nil {
							endpoints = append(endpoints, value)
						}
					}
				}
				result.Occurrences = append(result.Occurrences, Occurrence{source.ID, ref, fields, endpoints})
				if i == 0 {
					target = true
				} else {
					baseline = true
				}
				return nil
			})
			coverage.FileSHA256 = fileHash
			if errors.Is(err, os.ErrNotExist) {
				coverage.State = "absent"
				missing = true
			} else if err != nil {
				return result, err
			}
			result.Coverage = append(result.Coverage, coverage)
		}
	}
	for _, source := range sources {
		if err := Check(ctx, source.Directory, source.Binding); err != nil {
			return result, err
		}
	}
	if !missing && len(sources) > 1 {
		if !target {
			result.Novelty = "target-not-observed"
		} else if baseline {
			result.Novelty = "observed-in-included-baseline"
		} else {
			result.Novelty = "new-within-included-baseline"
		}
	}
	sort.Slice(result.Occurrences, func(i, j int) bool {
		a, b := result.Occurrences[i], result.Occurrences[j]
		if a.SourceID != b.SourceID {
			return a.SourceID < b.SourceID
		}
		if a.Reference.Type != b.Reference.Type {
			return a.Reference.Type < b.Reference.Type
		}
		x, _ := strconv.Atoi(a.Reference.Ordinal)
		y, _ := strconv.Atoi(b.Reference.Ordinal)
		return x < y
	})
	result.TotalOccurrences = len(result.Occurrences)
	snapshot := result
	snapshot.Limitations = nil
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return result, err
	}
	result.SnapshotSHA256 = Digest(encoded)
	return result, nil
}

type CataloguePage struct {
	Offset int `json:"offset"`
	Limit  int `json:"limit"`
}

func Paginate(result Catalogue, page *CataloguePage, expected string) (Catalogue, error) {
	if expected != "" && (!IsHash(expected) || expected != result.SnapshotSHA256) {
		return result, ErrStale
	}
	if page == nil {
		return result, nil
	}
	if page.Offset < 0 || page.Offset > len(result.Occurrences) || page.Limit < 1 || page.Limit > 200 || (page.Offset > 0 && expected == "") {
		return result, fmt.Errorf("page requires limit 1–200, valid offset and original snapshot after page zero")
	}
	end := min(len(result.Occurrences), page.Offset+page.Limit)
	result.Occurrences = result.Occurrences[page.Offset:end]
	if end < result.TotalOccurrences {
		next := end
		result.NextOffset = &next
	}
	return result, nil
}

func CatalogueFields() map[string]map[string][]string {
	out := map[string]map[string][]string{}
	for typ, kinds := range catalogueFields {
		out[typ] = map[string][]string{}
		for kind, fields := range kinds {
			out[typ][kind] = append([]string(nil), fields...)
		}
	}
	return out
}
