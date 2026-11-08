package enrichment

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const OwnerAuthorization = "Repository owner instructed completion and production publication of W66 optional enrichment, accepted the proposed first-party MIT catalogue grant, historical ODbL/DbCL derivative/source-offering obligations, and bounded IEEE secondary nonassertion evidence. This is an automated execution record of that instruction, not a human legal-review sign-off. Repository application code retains its existing license."
const firstPartyMIT = `MIT License

Copyright (c) 2026 Philipp Mieden

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`

// Combine binds real producer artifacts and their original evidence to one optional release.
// The original candidate provenance is retained verbatim alongside the later owner-authorized publication record.
func Combine(repo, kevDir, output string, now time.Time) error {
	read := func(path string) ([]byte, error) { return regular(path, MaxMember) }
	device := filepath.Join(repo, "internal/devicecatalog/channel")
	var sources []Source
	b, e := read(filepath.Join(device, SourcesName))
	if e != nil {
		return e
	}
	if e = decode(b, &sources); e != nil {
		return e
	}
	var kevSources []Source
	b, e = read(filepath.Join(kevDir, SourcesName))
	if e != nil {
		return e
	}
	if e = decode(b, &kevSources); e != nil {
		return e
	}
	sources = append(sources, kevSources...)
	members := map[string][]byte{}
	for _, n := range []string{"dhcp-fingerprints-odbl.json", "mac-organizations.json"} {
		b, e := read(filepath.Join(device, n))
		if e != nil {
			return e
		}
		members[n] = b
	}
	b, e = read(filepath.Join(kevDir, "kev.json"))
	if e != nil {
		return e
	}
	members["kev.json"] = b
	dp, e := read(filepath.Join(repo, "internal/devicecatalog/provenance.json"))
	if e != nil {
		return e
	}
	var notices strings.Builder
	notices.WriteString("Netcap optional enrichment: exact source and output records are in source-evidence.json.\n" + OwnerAuthorization + "\n\nDHCP derivative database: FingerBank / Inverse inc. (2008-2013), ODbL-1.0 AND DbCL-1.0. The complete derivative and full licenses are publicly offered at https://dbs.netcap.io/enrichment/signed/v1/latest and its authenticated full archive URL. SaaS users receive the same source offering. MAC organization names use the explicitly accepted secondary IEEE nonassertion evidence; this does not assert a new direct IEEE grant.\n\n")
	for i := range sources {
		if sources[i].ID == "fingerbank-odbl" || sources[i].ID == "mac-organizations" {
			sources[i].Evidence = string(dp)
		} else if sources[i].ID == "cisa-kev" {
			evidence, _ := json.Marshal(map[string]any{"origin": sources[i].Origin, "revision": sources[i].Revision, "input_sha256": sources[i].InputSHA256, "grant_sha256": sources[i].GrantSHA256, "transformation": sources[i].Transformation})
			sources[i].Evidence = string(evidence)
		}
	}
	for _, spec := range []struct{ dir, name, id string }{{"webtech", "webtech-descriptors.json", "webtech-descriptors"}, {"servicesignatures", "service-signatures.json", "netcap-service-signatures"}} {
		dir := filepath.Join(repo, "internal", spec.dir)
		data, e := read(filepath.Join(dir, spec.name))
		if e != nil {
			return e
		}
		proof, e := read(filepath.Join(dir, "provenance.json"))
		if e != nil {
			return e
		}
		var p map[string]json.RawMessage
		if e = decode(proof, &p); e != nil {
			return e
		}
		var claimed string
		if spec.id == "webtech-descriptors" {
			if e = json.Unmarshal(p["catalogue_sha256"], &claimed); e != nil {
				return e
			}
		} else {
			var c struct {
				SHA256 string `json:"sha256"`
			}
			if e = json.Unmarshal(p["catalogue"], &c); e != nil {
				return e
			}
			claimed = c.SHA256
		}
		if claimed != Digest(data) {
			return fmt.Errorf("stale provenance for %s", spec.name)
		}
		grant := firstPartyMIT
		origin := "Repository-owner-authorized W66 independent catalogue grant; source-evidence.json contains the original candidate provenance and subsequent automated publication record."
		if spec.id == "webtech-descriptors" {
			license, e := read(filepath.Join(dir, "NUCLEI-LICENSE.txt"))
			if e != nil {
				return e
			}
			if Digest(license) != "5fa6644d2dd1987a79c06f4af210d2cf8cfc4ee799999029d0f9980c9cf95a2c" {
				return fmt.Errorf("changed Nuclei MIT grant")
			}
			notice, e := read(filepath.Join(dir, "NOTICE.txt"))
			if e != nil {
				return e
			}
			grant += "\nUpstream transformed data grant and required notice:\n" + string(license) + "\n" + string(notice)
			origin += " https://github.com/projectdiscovery/nuclei-templates/blob/82ccd2a03568fed3c0c579d3c1df0997642e86dc/LICENSE.md"
		}
		members[spec.name] = data
		sources = append(sources, Source{ID: spec.id, Origin: "Netcap independently authored catalogue; provenance: internal/" + spec.dir + "/provenance.json", Revision: "provenance-sha256:" + Digest(proof), InputSHA256: Digest(proof), GrantOrigin: origin, GrantRevision: "W66 owner-authorized integration, 2026-11-06; pinned upstream revisions in evidence", GrantText: grant, GrantSHA256: Digest([]byte(grant)), Transformation: "Use the exact independently reviewed finite-parser catalogue bytes; retain original source, authorship, fixture and transformation evidence. No Nmap corpus, executable template interpreter, active probe or PoC payload.", Outputs: []File{{spec.name, Digest(data), int64(len(data))}}, Evidence: string(proof)})
	}
	if len(sources) != 5 || len(members) != 5 {
		return fmt.Errorf("combined release requires exactly five source families")
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].ID < sources[j].ID })
	for i := range sources {
		s := &sources[i]
		s.Review = &Review{Decision: "approved-for-publication", Reviewer: "OpenCode automated source/evidence review (openai/gpt-6.1-sol); no human counsel sign-off", ReviewID: "w66-optional-" + s.ID + "-" + s.Outputs[0].SHA256[:16], ReviewedAt: now.UTC().Format(time.RFC3339), Authorization: OwnerAuthorization, EvidenceSHA256: Digest([]byte(s.Evidence))}
		notices.WriteString("\n=== " + s.ID + " ===\nOrigin: " + s.Origin + "\nRevision: " + s.Revision + "\nInput SHA-256: " + s.InputSHA256 + "\nGrant origin: " + s.GrantOrigin + "\nGrant revision: " + s.GrantRevision + "\nTransformation: " + s.Transformation + "\n\n" + s.GrantText + "\n")
	}
	b, e = json.MarshalIndent(sources, "", "  ")
	if e != nil {
		return e
	}
	members[SourcesName] = b
	members[NoticesName] = []byte(notices.String())
	if e = os.Mkdir(output, 0700); e != nil {
		return e
	}
	for n, b := range members {
		if e = write(filepath.Join(output, n), b); e != nil {
			return e
		}
	}
	archive, p, e := Pack(output)
	if e != nil {
		return e
	}
	if e = write(filepath.Join(output, p.ArchiveSHA256+".tar.gz"), archive); e != nil {
		return e
	}
	pb, e := json.Marshal(p)
	if e != nil {
		return e
	}
	return write(filepath.Join(output, "unsigned-payload.json"), pb)
}

func validateReview(s Source) error {
	if s.Review == nil {
		return nil
	}
	r := s.Review
	if s.Evidence == "" || !json.Valid([]byte(s.Evidence)) || r.Decision != "approved-for-publication" || r.Reviewer == "" || r.ReviewID == "" || r.Authorization == "" || r.EvidenceSHA256 != Digest([]byte(s.Evidence)) {
		return fmt.Errorf("invalid enrichment review: %s", s.ID)
	}
	_, e := time.Parse(time.RFC3339, r.ReviewedAt)
	return e
}
