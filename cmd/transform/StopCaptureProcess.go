package transform

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/dreadl0ck/netcap/maltego"
)

func stopCaptureProcess() {

	trx := maltego.Transform{}
	log.Println("sending cleanup request")

	http.DefaultClient.Timeout = 0
	resp, err := http.Get("http://127.0.0.1:60589/cleanup")
	if err != nil && !errors.Is(err, io.EOF){
		trx.AddUIMessage("failed to stop process: "+err.Error(), maltego.UIMessageFatal)
		fmt.Println(trx.ReturnOutput())
		return
	}

	if err == nil {
		if resp.StatusCode != http.StatusOK {
			trx.AddUIMessage("failed to stop process: "+resp.Status, maltego.UIMessageFatal)
			fmt.Println(trx.ReturnOutput())
			return
		}
	}

	log.Println("done!")
	toLiveAuditRecords()
}
