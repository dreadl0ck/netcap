package transform

import (
	"fmt"
	"github.com/dreadl0ck/netcap/maltego"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"regexp"
	"strings"
)

func ToPhoneNumbersFromFile() {

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

	re := regexp.MustCompile(`(?:(?:\(?(?:00|\+)([1-4]\d\d|[1-9]\d?)\)?)?[\-\.\ \\\/]?)?((?:\(?\d{1,}\)?[\-\.\ \\\/]?){0,})(?:[\-\.\ \\\/]?(?:#|ext\.?|extension|x)[\-\.\ \\\/]?(\d+))?`)
	results := re.FindAllString(string(data), -1)
	if len(results) == 0 {
		log.Println("No phone numbers found")
		trx.AddUIMessage("completed!", "Inform")
		fmt.Println(trx.ReturnOutput())
		os.Exit(0)
	}

	log.Println("results",len(results), results)

	for _, r := range results {
		if len(r) > 5 {
			ent := trx.AddEntity("netcap.PhoneNumber", r)
			ent.AddProperty("properties.phonenumber", "Phone Number", "strict", r)
		}
	}

	trx.AddUIMessage("completed!", "Inform")
	fmt.Println(trx.ReturnOutput())
}
