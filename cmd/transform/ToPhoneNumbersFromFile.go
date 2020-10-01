package transform

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/nyaruka/phonenumbers"

	"github.com/dreadl0ck/netcap/maltego"
)

func toPhoneNumbersFromFile() {
	var (
		lt   = maltego.ParseLocalArguments(os.Args)
		trx  = &maltego.Transform{}
		path = strings.TrimPrefix(lt.Values["location"], "file://")
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

	re := regexp.MustCompile(`(?:(?:\(?(?:00|\+)([1-4]\d\d|[1-9]\d?)\)?)?[\-. \\/]?)?((?:\(?\d+\)?[\-. \\/]?)*)(?:[\-. \\/]?(?:#|ext\.?|extension|x)[\-. \\/]?(\d+))?`)
	results := re.FindAllString(string(data), -1)

	if len(results) == 0 {
		log.Println("No phone numbers found")
		trx.AddUIMessage("completed!", maltego.UIMessageInform)
		fmt.Println(trx.ReturnOutput())
		os.Exit(0)
	}

	log.Println("results", len(results), results)

	for _, r := range results {
		p, errParsePhone := phonenumbers.Parse(r, "US")
		if errParsePhone == nil {
			if phonenumbers.IsValidNumber(p) {
				ent := trx.AddEntityWithPath("netcap.PhoneNumber", r, path)
				ent.AddProperty("properties.phonenumber", "Phone Number", maltego.Strict, r)
			}
		}
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
