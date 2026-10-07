package flowexport

import "time"

type Envelope struct {
	Exporter      string `json:"exporter"`
	Collector     string `json:"collector"`
	ReceivedNs    int64  `json:"receivedNs,string"`
	PacketOrdinal uint64 `json:"packetOrdinal"`
}

type Field struct {
	ID                 uint16 `json:"id"`
	Enterprise         uint32 `json:"enterprise,omitempty"`
	EnterpriseProvided bool   `json:"enterpriseProvided,omitempty"`
	Scope              bool   `json:"scope,omitempty"`
	Value              []byte `json:"value"`
}

type Sampling struct {
	Status    string `json:"status"`
	Interval  uint64 `json:"interval,string"`
	Algorithm uint64 `json:"algorithm"`
	Scope     string `json:"scope"`
}

type Observation struct {
	Version            int      `json:"version"`
	ID                 string   `json:"id"`
	Envelope           Envelope `json:"envelope"`
	Format             string   `json:"format"`
	Domain             uint32   `json:"domain"`
	Sequence           uint32   `json:"sequence"`
	TemplateID         uint16   `json:"templateId,omitempty"`
	RecordOrdinal      int      `json:"recordOrdinal"`
	ExportNs           *int64   `json:"exportNs,omitempty,string"`
	StartNs            *int64   `json:"startNs,omitempty,string"`
	EndNs              *int64   `json:"endNs,omitempty,string"`
	TimeBasis          string   `json:"timeBasis"`
	ClockUncertaintyNs int64    `json:"clockUncertaintyNs,string"`
	SrcIP              string   `json:"srcIP"`
	DstIP              string   `json:"dstIP"`
	SrcPort            *uint64  `json:"srcPort,omitempty,string"`
	DstPort            *uint64  `json:"dstPort,omitempty,string"`
	Protocol           *uint64  `json:"protocol,omitempty"`
	TCPFlags           *uint64  `json:"tcpFlags,omitempty"`
	ICMPType           *uint64  `json:"icmpType,omitempty"`
	ICMPCode           *uint64  `json:"icmpCode,omitempty"`
	Ingress            *uint64  `json:"ingress,omitempty,string"`
	Egress             *uint64  `json:"egress,omitempty,string"`
	SrcAS              *uint64  `json:"srcAS,omitempty,string"`
	DstAS              *uint64  `json:"dstAS,omitempty,string"`
	SrcPrefixLength    *uint64  `json:"srcPrefixLength,omitempty"`
	DstPrefixLength    *uint64  `json:"dstPrefixLength,omitempty"`
	NextHop            string   `json:"nextHop,omitempty"`
	Bytes              *uint64  `json:"bytes,omitempty,string"`
	Packets            *uint64  `json:"packets,omitempty,string"`
	CounterSemantics   string   `json:"counterSemantics"`
	Sampling           Sampling `json:"sampling"`
	ActiveTimeout      *uint64  `json:"activeTimeoutSeconds,omitempty"`
	IdleTimeout        *uint64  `json:"idleTimeoutSeconds,omitempty"`
	Fields             []Field  `json:"fields"`
	Limitations        []string `json:"limitations"`
}

type Issue struct {
	Code       string   `json:"code"`
	Detail     string   `json:"detail"`
	Envelope   Envelope `json:"envelope"`
	TemplateID uint16   `json:"templateId,omitempty"`
}

type Batch struct {
	Observations []Observation `json:"observations"`
	Issues       []Issue       `json:"issues"`
}

type Health struct {
	Version                 int      `json:"version"`
	Datagrams               uint64   `json:"datagrams"`
	Records                 uint64   `json:"records"`
	Malformed               uint64   `json:"malformed"`
	MissingTemplates        uint64   `json:"missingTemplates"`
	ExpiredTemplates        uint64   `json:"expiredTemplates"`
	SequenceDiscontinuities uint64   `json:"sequenceDiscontinuities"`
	PossibleRestarts        uint64   `json:"possibleRestarts"`
	Duplicates              uint64   `json:"duplicates"`
	StateLimitExceeded      uint64   `json:"stateLimitExceeded"`
	Limitations             []string `json:"limitations"`
}

type Config struct {
	TemplateTTL  time.Duration
	MaxDomains   int
	MaxTemplates int
	MaxFields    int
}

func DefaultConfig() Config {
	return Config{TemplateTTL: 30 * time.Minute, MaxDomains: 128, MaxTemplates: 1024, MaxFields: 256}
}
