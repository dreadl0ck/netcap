/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package transform

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/dreadl0ck/maltego"
)

func stopCaptureProcess() {
	trx := &maltego.Transform{}
	log.Println("sending cleanup request")

	http.DefaultClient.Timeout = 0
	resp, err := http.Get("http://127.0.0.1:60589/cleanup")
	if err != nil && !errors.Is(err, io.EOF) {
		trx.AddUIMessage("failed to stop process: "+err.Error(), maltego.UIMessageFatal)
		fmt.Println(trx.ReturnOutput())
		return
	}
	defer resp.Body.Close()

	if err == nil {
		if resp.StatusCode != http.StatusOK {
			trx.AddUIMessage("failed to stop process: "+resp.Status, maltego.UIMessageFatal)
			fmt.Println(trx.ReturnOutput())
			return
		}
	}

	defer func() {
		if errPanic := recover(); err != nil {
			maltego.Die(errPanic.(error).Error(), "process panic")
		}
	}()

	log.Println("done!")
	time.Sleep(3 * time.Second)
	toLiveAuditRecords()
}
