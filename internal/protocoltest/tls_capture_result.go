package protocoltest

type TLSCaptureResult struct {
	Node0Text        string            `json:"node0Text,omitempty"`
	Node1Text        string            `json:"node1Text,omitempty"`
	HTTP2            []TLSHTTP2Message `json:"http2,omitempty"`
	DecodeErrors     []string          `json:"decodeErrors,omitempty"`
	Version          int               `json:"version"`
	InputSHA256      string            `json:"inputSHA256"`
	KeyLogSHA256     string            `json:"keyLogSHA256"`
	ToolVersion      string            `json:"toolVersion"`
	Stream           int               `json:"stream"`
	StreamIndexField string            `json:"streamIndexField,omitempty"`
	Client           []byte            `json:"node0Bytes"`
	Server           []byte            `json:"node1Bytes"`
	ClientSHA256     string            `json:"node0SHA256"`
	ServerSHA256     string            `json:"node1SHA256"`
	Nodes            []string          `json:"nodes"`
	Limitations      []string          `json:"limitations"`
}
