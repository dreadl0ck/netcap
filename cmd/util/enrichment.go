package util

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/dreadl0ck/netcap/internal/dbs"
	"github.com/dreadl0ck/netcap/internal/enrichment"
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/urfave/cli/v3"
)

func runEnrichment(c *cli.Command) (bool, error) {
	if cert := c.String("delegate-enrichment"); cert != "" {
		trust, e := dbs.CommunitySigningRoot()
		if e != nil {
			return true, e
		}
		return true, enrichment.DelegateExistingSigner(c.String("enrichment-root-key"), cert, c.String("enrichment-certificate"), trust, time.Now())
	}
	if dir := c.String("sign-enrichment"); dir != "" {
		trust, e := dbs.CommunitySigningRoot()
		if e != nil {
			return true, e
		}
		return true, enrichment.SignPublication(dir, c.String("enrichment-key"), c.String("enrichment-certificate"), c.Uint64("enrichment-sequence"), trust, time.Now())
	}
	if dir := c.String("serve-enrichment"); dir != "" {
		trust, e := dbs.CommunitySigningRoot()
		if e != nil {
			return true, e
		}
		handler, e := enrichment.Handler(dir, trust)
		if e != nil {
			return true, e
		}
		server := &http.Server{Addr: c.String("enrichment-addr"), Handler: handler, ReadHeaderTimeout: 10 * time.Second}
		return true, server.ListenAndServe()
	}
	if c.Bool("download-enrichment") {
		root := c.String("enrichment-root")
		if root == "" {
			root = enrichment.Root(resolvers.ConfigRootPath)
		}
		trust, e := dbs.CommunitySigningRoot()
		if e != nil {
			return true, e
		}
		return true, enrichment.Download(root, c.String("enrichment-url"), trust)
	}
	if input := c.String("build-kev"); input != "" {
		out, source, e := enrichment.BuildKEVFiles(input, c.String("kev-license"))
		if e != nil {
			return true, e
		}
		dir := c.String("enrichment-output")
		if e = os.Mkdir(dir, 0700); e != nil {
			return true, e
		}
		sources, e := json.Marshal([]enrichment.Source{source})
		if e != nil {
			return true, e
		}
		notices := []byte(fmt.Sprintf("CISA Known Exploited Vulnerabilities\nOrigin: %s\nRevision: %s\nInput SHA-256: %s\nGrant SHA-256: %s\n\nFederal due dates are CISA federal remediation deadlines, not universal customer deadlines.\nRansomware Unknown is not a negative assertion. References are links only; no referenced bodies are acquired.\n\n%s", source.Origin, source.Revision, source.InputSHA256, source.GrantSHA256, source.GrantText))
		for name, data := range map[string][]byte{"kev.json": out, enrichment.SourcesName: sources, enrichment.NoticesName: notices} {
			if e = os.WriteFile(filepath.Join(dir, name), data, 0600); e != nil {
				return true, e
			}
		}
		fmt.Fprintf(c.Writer, "KEV candidate: %s (1768 distinct CVEs, revision %s; unsigned)\n", dir, enrichment.KEVRevision)
		return true, nil
	}
	if dir := c.String("pack-enrichment"); dir != "" {
		archive, p, e := enrichment.Pack(dir)
		if e != nil {
			return true, e
		}
		out := c.String("enrichment-output")
		if e = os.Mkdir(out, 0700); e != nil {
			return true, e
		}
		if e = os.WriteFile(filepath.Join(out, p.ArchiveSHA256+".tar.gz"), archive, 0600); e != nil {
			return true, e
		}
		b, e := json.Marshal(p)
		if e != nil {
			return true, e
		}
		return true, os.WriteFile(filepath.Join(out, "unsigned-payload.json"), b, 0600)
	}
	return false, nil
}
