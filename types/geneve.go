package types

import (
	"encoding/hex"
	"strconv"
	"strings"
)

func (i Geneve) CSVHeader() []string {
	return filter([]string{
		"Timestamp",
		"Version",        // int32
		"OptionsLength",  // int32
		"OAMPacket",      // bool
		"CriticalOption", // bool
		"Protocol",       // int32
		"VNI",            // uint32
		"Options",        // []*GeneveOption
	})
}

func (i Geneve) CSVRecord() []string {
	var opts []string
	for _, o := range i.Options {
		opts = append(opts, o.ToString())
	}
	return filter([]string{
		formatTimestamp(i.Timestamp),
		formatInt32(i.Version),               // int32
		formatInt32(i.OptionsLength),         // int32
		strconv.FormatBool(i.OAMPacket),      // bool
		strconv.FormatBool(i.CriticalOption), // bool
		formatInt32(i.Protocol),              // int32
		formatUint32(i.VNI),                  // uint32
		strings.Join(opts, ""),               // []*GeneveOption
	})
}

func (i Geneve) NetcapTimestamp() string {
	return i.Timestamp
}

func (i GeneveOption) ToString() string {

	var b strings.Builder
	b.WriteString(begin)
	b.WriteString(formatInt32(i.Class))
	b.WriteString(sep)
	b.WriteString(formatInt32(i.Type))
	b.WriteString(sep)
	b.WriteString(formatInt32(i.Flags))
	b.WriteString(sep)
	b.WriteString(formatInt32(i.Length))
	b.WriteString(sep)
	b.WriteString(hex.EncodeToString(i.Data))
	b.WriteString(end)

	return b.String()
}
