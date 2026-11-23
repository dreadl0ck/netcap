// Package auditname maps audit file names to the record types stored in them.
package auditname

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/dreadl0ck/netcap/types"
)

// auditFileAliases lists audit file base names that differ from the record
// type stored in them. VRRP and ApplePktap are gopacket layer names the writer
// uses for NC_VRRPv2 and NC_PKTAP; GTPv1U is the pre-v0.16.12 name of GTP.ncap.gz.
var auditFileAliases = []struct{ file, typ string }{
	{file: "VRRP", typ: "VRRPv2"},
	{file: "ApplePktap", typ: "PKTAP"},
	{file: "GTPv1U", typ: "GTP"},
}

// Suffixes are the protobuf audit suffixes in read preference order.
var Suffixes = []string{".ncap.gz", ".ncap"}

// TypeForFile returns the record type name stored in an audit file with
// the given base name (no suffix), or "" when the name is not an audit type.
func TypeForFile(base string) string {
	for _, alias := range auditFileAliases {
		if base == alias.file {
			return alias.typ
		}
	}
	if _, ok := types.Type_value["NC_"+base]; ok && base != "" {
		return base
	}
	return ""
}

// Alias returns the record type for a file-name alias, ignoring case.
func Alias(name string) (string, bool) {
	for _, alias := range auditFileAliases {
		if strings.EqualFold(name, alias.file) {
			return alias.typ, true
		}
	}
	return "", false
}

// FileBases returns the file base names that may hold typeName, the type
// name first. Unknown types return only typeName.
func FileBases(typeName string) []string {
	bases := []string{typeName}
	for _, alias := range auditFileAliases {
		if alias.typ == typeName {
			bases = append(bases, alias.file)
		}
	}
	return bases
}

// Candidates returns every file name that may hold typeName, in read
// preference order: canonical base before aliases, compressed before plain.
func Candidates(typeName string) []string {
	var names []string
	for _, base := range FileBases(typeName) {
		for _, suffix := range Suffixes {
			names = append(names, base+suffix)
		}
	}
	return names
}

// Parse parses an audit file name with a protobuf, CSV or JSON
// suffix and returns its base name and the record type it holds.
func Parse(name string) (base, typ string, ok bool) {
	for _, suffix := range []string{".ncap.gz", ".ncap", ".csv.gz", ".csv", ".json.gz", ".json"} {
		if strings.HasSuffix(name, suffix) {
			base = strings.TrimSuffix(name, suffix)
			typ = TypeForFile(base)
			return base, typ, typ != ""
		}
	}
	return "", "", false
}

// Resolve returns the existing regular audit file in dir holding
// typeName. It does not follow symlinks.
func Resolve(dir, typeName string) (string, error) {
	for _, name := range Candidates(typeName) {
		info, err := os.Lstat(filepath.Join(dir, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		if !info.Mode().IsRegular() {
			return "", &os.PathError{Op: "open", Path: filepath.Join(dir, name), Err: errors.New("not a regular file")}
		}
		return filepath.Join(dir, name), nil
	}
	return "", os.ErrNotExist
}
