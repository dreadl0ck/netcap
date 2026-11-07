package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/dreadl0ck/netcap/internal/dbs"
	"github.com/dreadl0ck/netcap/internal/enrichment"
)

func main() {
	mode := flag.String("mode", "serve", "serve, combine, kev, delegate, sign, verify, or install")
	dir := flag.String("root", "", "publication or installation directory")
	repo := flag.String("repo", "", "frozen Netcap artifact/source tree")
	kev := flag.String("kev", "", "KEV candidate directory")
	out := flag.String("output", "", "new output directory or certificate path")
	key := flag.String("key", "", "existing private key file (never printed)")
	cert := flag.String("certificate", "", "existing public certificate file")
	sequence := flag.Uint64("sequence", 0, "monotonic optional-channel sequence")
	addr := flag.String("addr", ":8080", "listener")
	input := flag.String("input", "", "acquired KEV JSON")
	grant := flag.String("grant", "", "full upstream CC0 LICENSE")
	revision := flag.String("revision", "", "immutable KEV revision")
	hash := flag.String("input-sha256", "", "acquired KEV input SHA-256")
	server := flag.String("server", "https://dbs.netcap.io", "optional channel server")
	flag.Parse()
	trust, e := dbs.CommunitySigningRoot()
	if e != nil {
		log.Fatal(e)
	}
	now := time.Now()
	switch *mode {
	case "combine":
		e = enrichment.Combine(*repo, *kev, *out, now)
	case "kev":
		var data []byte
		var source enrichment.Source
		data, source, e = enrichment.BuildKEVSnapshotFiles(*input, *grant, *revision, *hash)
		if e == nil {
			e = os.Mkdir(*out, 0700)
		}
		if e == nil {
			b, _ := json.Marshal([]enrichment.Source{source})
			for name, b := range map[string][]byte{"kev.json": data, enrichment.SourcesName: b, enrichment.NoticesName: []byte(source.GrantText)} {
				if e = os.WriteFile(filepath.Join(*out, name), b, 0600); e != nil {
					break
				}
			}
		}
	case "delegate":
		e = enrichment.DelegateExistingSigner(*key, *cert, *out, trust, now)
	case "sign":
		e = enrichment.SignPublication(*dir, *key, *cert, *sequence, trust, now)
	case "verify":
		e = enrichment.VerifyPublication(*dir, trust, now)
	case "baseline":
		var count int
		count, e = enrichment.PreviousKEVCount(*dir, trust, now)
		if e == nil {
			fmt.Println(count)
		}
	case "install":
		e = enrichment.Download(*dir, *server, trust)
	case "serve":
		var handler http.Handler
		handler, e = enrichment.LiveHandler(*dir, trust)
		if e == nil {
			srv := &http.Server{Addr: *addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
			e = srv.ListenAndServe()
		}
	default:
		e = fmt.Errorf("unsupported enrichment mode %q", *mode)
	}
	if e != nil {
		log.Fatal(e)
	}
}
