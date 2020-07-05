package transform

import (
	"fmt"
	"github.com/dreadl0ck/netcap/maltego"
	"io/ioutil"
	"log"
	"mvdan.cc/xurls/v2"
	"net/url"
	"os"
	"strings"
)

func ToLinksFromFile() {

	var (
		lt              = maltego.ParseLocalArguments(os.Args)
		trx             = &maltego.MaltegoTransform{}
		path = lt.Values["location"]
		err error
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

	rxStrict := xurls.Strict()
	results := rxStrict.FindAllString(string(data), -1)

	if len(results) == 0 {
			log.Println("No links found")
			trx.AddUIMessage("completed!", "Inform")
			fmt.Println(trx.ReturnOutput())
			os.Exit(0)
	}

	log.Println("results", results)

	for _, r := range results {
		ent := trx.AddEntity("netcap.URL", r)

		// since netcap.URL is inheriting from maltego.URL, in order to set the URL field correctly, we need to prefix the id with properties.
		ent.AddProperty("properties.url", "URL", "strict", r)
	}

	trx.AddUIMessage("completed!", "Inform")
	fmt.Println(trx.ReturnOutput())
}
