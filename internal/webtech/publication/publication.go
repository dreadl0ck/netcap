// Package publication prepares the two optional catalogues and their scoped
// source evidence. It neither signs nor publishes a release.
package publication

import (
	"encoding/json"
	"github.com/dreadl0ck/netcap/internal/enrichment"
	"github.com/dreadl0ck/netcap/internal/servicesignatures"
	"github.com/dreadl0ck/netcap/internal/webtech"
)

func Members() (map[string][]byte, error) {
	a := webtech.ResourceAttribution()
	webGrant := a.FirstPartyGrant + "\n" + a.ThirdPartyGrant
	members := map[string][]byte{webtech.FileName: webtech.DescriptorBytes(), servicesignatures.FileName: servicesignatures.PublicationBytes()}
	sources := []enrichment.Source{
		{ID: "webtech-descriptors", Origin: "urn:netcap:webtech:owner-and-upstream-evidence", Revision: "w66-passive-webtech-automated-20261106", InputSHA256: enrichment.Digest(a.Review), GrantOrigin: "urn:netcap:owner-authorization:w66-integration-and-nuclei-mit", GrantRevision: "owner-authorized-2026-11-06;nuclei-82ccd2a03568fed3c0c579d3c1df0997642e86dc", GrantText: webGrant, GrantSHA256: enrichment.Digest([]byte(webGrant)), Transformation: "Independently authored WordPress/Drupal output-fact selectors plus MIT Nuclei Hugo/Joomla generator tokens; parsed passive GET/200 only; preserve daffainfo/ricardomaia and ProjectDiscovery copyright; no requests, redirects, DSL, JS or CPE claims", Outputs: []enrichment.File{{Path: webtech.FileName, SHA256: enrichment.Digest(members[webtech.FileName]), Size: int64(len(members[webtech.FileName]))}}},
		{ID: "netcap-service-signatures", Origin: "urn:netcap:independent-protocol-grammar", Revision: "w66-four-service-rules-automated-20261106", InputSHA256: enrichment.Digest(servicesignatures.ResourceAttribution()), GrantOrigin: "urn:netcap:owner-authorization:w66-integration", GrantRevision: "owner-authorized-2026-11-06-to-extent-owned", GrantText: a.FirstPartyGrant, GrantSHA256: enrichment.Digest([]byte(a.FirstPartyGrant)), Transformation: "Four independently expressed protocol descriptor IDs and synthetic fixtures from cited RFC facts; no raw Nmap corpus; existing GPL engine/parser code unchanged in license", Outputs: []enrichment.File{{Path: servicesignatures.FileName, SHA256: enrichment.Digest(members[servicesignatures.FileName]), Size: int64(len(members[servicesignatures.FileName]))}}},
	}
	for i, proof := range [][]byte{a.Review, servicesignatures.ResourceAttribution()} {
		var review struct {
			ID string `json:"review_id"`
			At string `json:"reviewed_at"`
		}
		if err := json.Unmarshal(proof, &review); err != nil {
			return nil, err
		}
		sources[i].Evidence = string(proof)
		sources[i].Review = &enrichment.Review{Decision: "approved-for-publication", Reviewer: "OpenAI gpt-6.1-sol (automated AI)", ReviewID: review.ID, ReviewedAt: review.At, Authorization: "User-owner explicitly authorized completion and permissive descriptor/fixture rights to the extent owned. No human-authorship or human legal-review attestation; existing GPL runtime/parser code unchanged in license.", EvidenceSHA256: enrichment.Digest(proof)}
	}
	data, err := json.MarshalIndent(sources, "", "  ")
	if err != nil {
		return nil, err
	}
	members[enrichment.SourcesName] = append(data, '\n')
	members[enrichment.NoticesName] = []byte(a.Notice + "\n" + webGrant + "\nService catalogue authorship and review:\n" + string(servicesignatures.ResourceAttribution()) + "\nWebtech authorship and review:\n" + string(a.Review))
	return members, nil
}
