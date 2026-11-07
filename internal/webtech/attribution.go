package webtech

import (
	_ "embed"
	"encoding/json"
)

//go:embed NOTICE.txt
var notice string

//go:embed FIRST-PARTY-LICENSE.txt
var firstPartyGrant string

//go:embed NUCLEI-LICENSE.txt
var nucleiGrant string

//go:embed provenance.json
var provenance []byte

type Attribution struct {
	Review          json.RawMessage `json:"review"`
	Notice          string          `json:"notice"`
	FirstPartyGrant string          `json:"first_party_grant"`
	ThirdPartyGrant string          `json:"third_party_grant"`
}

func ResourceAttribution() Attribution {
	return Attribution{append([]byte{}, provenance...), notice, firstPartyGrant, nucleiGrant}
}
func DescriptorBytes() []byte { return append([]byte{}, descriptors...) }
