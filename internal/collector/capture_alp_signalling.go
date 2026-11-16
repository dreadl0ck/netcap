package collector

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/dreadl0ck/netcap/internal/linkaudit"
)

type alpMulticast struct {
	Source, Destination         string
	SourcePort, DestinationPort uint16
	SID, ContextID              *uint8 `json:",omitempty"`
}
type alpPLP struct {
	ID         uint8
	Multicasts []alpMulticast
}

func parseALPLMT(data []byte) ([]alpPLP, error) {
	if len(data) == 0 {
		return nil, io.ErrUnexpectedEOF
	}
	count, offset, entries := int(data[0]>>2)+1, 1, 0
	var plps []alpPLP
	for range count {
		if len(data)-offset < 2 {
			return nil, io.ErrUnexpectedEOF
		}
		plp := alpPLP{ID: data[offset] >> 2}
		n := int(data[offset+1])
		offset += 2
		entries += n
		if entries > 4096 {
			return nil, fmt.Errorf("ALP LMT entry limit exceeded")
		}
		for range n {
			if len(data)-offset < 13 {
				return nil, io.ErrUnexpectedEOF
			}
			item := alpMulticast{Source: net.IP(data[offset : offset+4]).String(), Destination: net.IP(data[offset+4 : offset+8]).String(), SourcePort: binary.BigEndian.Uint16(data[offset+8:]), DestinationPort: binary.BigEndian.Uint16(data[offset+10:])}
			flags := data[offset+12]
			offset += 13
			if flags&0x80 != 0 {
				if offset == len(data) {
					return nil, io.ErrUnexpectedEOF
				}
				value := data[offset]
				item.SID = &value
				offset++
			}
			if flags&0x40 != 0 {
				if offset == len(data) {
					return nil, io.ErrUnexpectedEOF
				}
				value := data[offset]
				item.ContextID = &value
				offset++
			}
			plp.Multicasts = append(plp.Multicasts, item)
		}
		plps = append(plps, plp)
	}
	if offset != len(data) {
		return nil, fmt.Errorf("ALP LMT has trailing bytes")
	}
	return plps, nil
}

func decodeALPSignalling(f *linkaudit.LinkFrame, data []byte, lengths []int) {
	if len(lengths) == 0 {
		lengths = []int{len(data)}
	}
	var tables []any
	offset := 0
	decodedBytes := 0
	var decodedPayload []byte
	var decodedLengths []int
	for _, n := range lengths {
		if n <= 0 || n > len(data)-offset {
			f.Qualifications = append(f.Qualifications, "invalid-ALP-signalling-length")
			return
		}
		body := data[offset : offset+n]
		offset += n
		format, encoding := f.Fields["signalling_format"], f.Fields["signalling_encoding"]
		if format == "0" && encoding != "0" {
			f.Qualifications = append(f.Qualifications, "invalid-ALP-binary-signalling-encoding")
			return
		}
		switch encoding {
		case "0":
		case "1":
			reader := flate.NewReader(bytes.NewReader(body))
			decoded, err := io.ReadAll(io.LimitReader(reader, (1<<20)+1))
			_ = reader.Close()
			if err != nil || len(decoded) > 1<<20 {
				f.Qualifications = append(f.Qualifications, "ALP-signalling-deflate-invalid-or-limit")
				return
			}
			body = decoded
		default:
			f.Qualifications = append(f.Qualifications, "ALP-signalling-encoding-not-supported")
			return
		}
		decodedBytes += len(body)
		if decodedBytes > 1<<20 {
			f.Qualifications = append(f.Qualifications, "ALP-signalling-decoded-byte-limit")
			return
		}
		decodedPayload = append(decodedPayload, body...)
		decodedLengths = append(decodedLengths, len(body))
		switch format {
		case "0":
			if f.Fields["signalling_type"] != "1" || f.Fields["signalling_type_extension"] != "65535" {
				f.Qualifications = append(f.Qualifications, "ALP-signalling-table-not-decoded")
				return
			}
			plps, err := parseALPLMT(body)
			if err != nil {
				f.Qualifications = append(f.Qualifications, "invalid-ALP-link-mapping-table")
				return
			}
			tables = append(tables, plps)
		case "2":
			if !utf8.Valid(body) || !json.Valid(body) {
				f.Qualifications = append(f.Qualifications, "invalid-ALP-signalling-JSON")
				return
			}
			tables = append(tables, map[string]any{"format": "json", "decoded_length": len(body)})
		case "1":
			d := xml.NewDecoder(bytes.NewReader(body))
			depth := 0
			root := false
			for {
				token, err := d.Token()
				if err == io.EOF {
					break
				}
				if err != nil {
					f.Qualifications = append(f.Qualifications, "invalid-ALP-signalling-XML")
					return
				}
				switch token.(type) {
				case xml.StartElement:
					if depth == 0 && root {
						f.Qualifications = append(f.Qualifications, "invalid-ALP-signalling-XML")
						return
					}
					root = true
					depth++
				case xml.EndElement:
					depth--
				case xml.CharData:
					if depth == 0 && len(bytes.TrimSpace(token.(xml.CharData))) != 0 {
						f.Qualifications = append(f.Qualifications, "invalid-ALP-signalling-XML")
						return
					}
				}
				if depth > 64 {
					f.Qualifications = append(f.Qualifications, "ALP-signalling-XML-depth-limit")
					return
				}
			}
			if !root {
				f.Qualifications = append(f.Qualifications, "invalid-ALP-signalling-XML")
				return
			}
			tables = append(tables, map[string]any{"format": "xml", "decoded_length": len(body)})
		default:
			f.Qualifications = append(f.Qualifications, "ALP-signalling-format-not-supported")
			return
		}
	}
	encoded, _ := json.Marshal(tables)
	f.Fields["signalling_tables"] = string(encoded)
	f.Fields["signalling_table_count"] = strconv.Itoa(len(tables))
	if f.Fields["signalling_format"] != "0" {
		f.Qualifications = append(f.Qualifications, "ALP-signalling-schema-not-decoded")
	}
	markLinkDecoded(f, "ALP-signalling")
	f.Fields["decoded_payload_length"] = strconv.Itoa(len(decodedPayload))
	parts := make([]string, len(decodedLengths))
	for i, n := range decodedLengths {
		parts[i] = strconv.Itoa(n)
	}
	f.Fields["decoded_component_lengths"] = strings.Join(parts, ",")
	f.Decoded = decodedPayload
}
