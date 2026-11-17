package evidence

const SourceOffsetNamespace = "decompressed-input-bytes"

func packetOrdinalNamespaces(kind string) map[string]string {
	name := "capture-ingress-one-based"
	if kind == "file" {
		name = "input-packet-one-based"
	}
	return map[string]string{"packetReferences": name, "retainedPacketIDs": name, "retainedSegmentBounds": "capture-ingress-zero-based", "flowExportOrdinal": "capture-ingress-zero-based"}
}

type SourcePacket struct {
	Ordinal           uint64 `json:"ordinal,string"`
	Offset            int64  `json:"offset,omitempty,string"`
	OffsetNamespace   string `json:"offsetNamespace,omitempty"`
	OffsetKind        string `json:"offsetKind,omitempty"`
	Section           uint64 `json:"section,omitempty"`
	Interface         uint32 `json:"interface,omitempty"`
	ByteOrder         string `json:"byteOrder,omitempty"`
	TimestampEncoding string `json:"timestampEncoding,omitempty"`
	TimestampSeconds  uint64 `json:"timestampSeconds,omitempty,string"`
	TimestampFraction uint32 `json:"timestampFraction,omitempty"`
	TimestampTicks    uint64 `json:"timestampTicks,omitempty,string"`
	TimestampUnits    uint64 `json:"timestampUnits,omitempty,string"`
	TimestampOffset   int64  `json:"timestampOffset,omitempty,string"`
	SHA256            string `json:"packetSHA256,omitempty"`
}
