package transform

import (
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toHTTPUniformResourceLocators() {
	urlStats := make(map[string]int)

	maltego.HTTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, h *types.HTTP, min, max uint64, path string, ipaddr string) {
			if h.SrcIP == ipaddr || h.DstIP == ipaddr {
				if h.URL == "" {
					return
				}

				bareURL := stripQueryString(h.URL)
				log.Println(bareURL)

				ent := trx.AddEntityWithPath("netcap.URL", bareURL, path)

				// since netcap.URL is inheriting from maltego.URL, in order to set the URL field correctly, we need to prefix the id with properties.
				ent.AddProperty("properties.url", "URL", maltego.Strict, bareURL)
				ent.AddProperty("host", "Host", maltego.Strict, h.Host)
				ent.AddProperty(maltego.PropertyIpAddr, maltego.PropertyIpAddrLabel, maltego.Strict, ipaddr)

				urlStats[bareURL]++
				ent.SetLinkLabel(strconv.Itoa(urlStats[bareURL]) + "\n" + h.Method)

				// ent.AddDisplayInformation(createURLTableHTML(h, "SourceIP", h.SrcIP), "Visitors")
				// ent.AddDisplayInformation(createURLTableHTML(h, "DestinationIP", h.DstIP), "Providers")

				ent.AddDisplayInformation("<pre>"+utils.UnixTimeToUTC(h.Timestamp)+"    |    "+h.SrcIP+"    |    "+h.Method+"    |    "+strconv.Itoa(int(h.StatusCode))+"    |    "+http.StatusText(int(h.StatusCode))+"<br>", "Visitors")
				ent.AddDisplayInformation("<pre>"+utils.UnixTimeToUTC(h.Timestamp)+"    |    "+h.DstIP+"    |    "+h.Method+"    |    "+strconv.Itoa(int(h.StatusCode))+"    |    "+http.StatusText(int(h.StatusCode))+"<br>", "Providers")
			}
		},
		false,
	)
}

func createURLTableHTML(h *types.HTTP, ipType, ip string) string {
	out := []string{"<table style='width:100%'>"}

	out = append(out, `<tr>
    <th>Timestamp</th>
    <th>`+ipType+`</th>
	<th>StatusCode</th>
	<th>StatusText</th>
  </tr>`)

	out = append(out, "<tr><td>"+utils.UnixTimeToUTC(h.Timestamp)+"</td><td>"+ip+"</td><td>"+strconv.Itoa(int(h.StatusCode))+"</td><td>"+http.StatusText(int(h.StatusCode))+"</td></tr>")

	// colors
	// out = append(out, "<tr><td style='color:red'>"+k+"</td><td>"+v+"</td></tr>")

	// out = append(out, "</table>")

	return strings.Join(out, "")
}

func stripQueryString(inputUrl string) string {
	u, err := url.Parse(inputUrl)
	if err != nil {
		panic(err)
	}
	u.RawQuery = ""
	return u.String()
}
