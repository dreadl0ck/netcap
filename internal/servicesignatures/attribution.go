package servicesignatures

import (
	_ "embed"
	"encoding/json"
)

//go:embed service-signatures.json
var publication []byte

//go:embed provenance.json
var provenance []byte

func PublicationBytes() []byte             { return append([]byte{}, publication...) }
func ResourceAttribution() json.RawMessage { return append([]byte{}, provenance...) }
