package transform

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/mcnijman/go-emailaddress"

	"github.com/dreadl0ck/netcap/maltego"
)

func toEmailsFromFile() {
	var (
		lt   = maltego.ParseLocalArguments(os.Args)
		trx  = &maltego.Transform{}
		path = lt.Values["location"]
		err  error
	)
	log.Println(lt.Values)

	if path == "" {
		path, err = url.QueryUnescape(lt.Values["properties.url"])
		if err != nil {
			log.Fatal(err)
		}
	}

	path = strings.TrimPrefix(path, "file://")

	log.Println("file path:", path)

	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}

	results := emailaddress.Find(data, false)
	if len(results) == 0 {
		log.Println("No emails found")
		trx.AddUIMessage("completed!", "Inform")
		fmt.Println(trx.ReturnOutput())
		os.Exit(0)
	}

	log.Println("results", results)

	for _, r := range results {
		trx.AddEntity("netcap.Email", r.String())
	}

	trx.AddUIMessage("completed!", "Inform")
	fmt.Println(trx.ReturnOutput())
}
