package transform

import (
	"fmt"
	"log"
	"net/http"

	"github.com/dreadl0ck/netcap/maltego"
)

func stopCaptureProcess() {
	var (
		//lt = maltego.ParseLocalArguments(os.Args[1:])
		trx = maltego.Transform{}
	)

	log.Println("sending cleanup request")

	// TODO: flush all remaining audit records to maltego on exit: remove timeout, make the request blocking and wait for it, then invoke toLiveAuditRecords
	http.DefaultClient.Timeout = 0
	resp, err := http.Get("http://127.0.0.1:60589/cleanup")
	if err != nil {
		trx.AddUIMessage("failed to stop process: "+err.Error(), maltego.UIMessageFatal)
		fmt.Println(trx.ReturnOutput())
		return
	}

	if resp.StatusCode != http.StatusOK {
		trx.AddUIMessage("failed to stop process: "+resp.Status, maltego.UIMessageFatal)
		fmt.Println(trx.ReturnOutput())
		return
	}

	log.Println("done!")
	toLiveAuditRecords()
}
