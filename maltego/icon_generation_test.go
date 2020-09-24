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

package maltego_test

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/png"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/fogleman/gg"
	"github.com/go-git/go-git/v5"
	"github.com/nfnt/resize"

	"github.com/dreadl0ck/netcap/decoder"
)

// Icons/Netcap/sim_card_alert.xml
var icon = `<Icon>
<Aliases/>
</Icon>`

func TestGenerateAuditRecordIcons(t *testing.T) {
	generateIcons()
	generateAdditionalIcons()

	decoder.ApplyActionToCustomDecoders(func(d decoder.CustomDecoderAPI) {
		fmt.Println(d.GetName())
		generateAuditRecordIcon(d.GetName())
	})

	decoder.ApplyActionToGoPacketDecoders(func(e *decoder.GoPacketDecoder) {
		name := strings.ReplaceAll(e.Layer.String(), "/", "")
		fmt.Println(name)
		generateAuditRecordIcon(name)
	})
}

// Utils

func generateIcons() {
	_ = os.RemoveAll("/tmp/icons")

	_, err := git.PlainClone("/tmp/icons", false, &git.CloneOptions{
		URL:      "https://github.com/dreadl0ck/material-icons-png.git",
		Progress: os.Stdout,
	})

	if err != nil && !errors.Is(err, git.ErrRepositoryAlreadyExists) {
		log.Fatal(err)
	}

	fmt.Println("cloned icon repository to", "/tmp/icons")

	// rename icons
	_ = os.Mkdir("/tmp/icons/renamed", 0o700)

	files, err := ioutil.ReadDir("/tmp/icons/png/black")
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		fmt.Println(f.Name())

		var (
			oldPath = filepath.Join("/tmp", "icons", "png", "black", filepath.Base(f.Name()), "twotone-4x.png")
			newBase = filepath.Join("/tmp", "icons", "renamed", filepath.Base(f.Name()))
			newPath = newBase + ".png"
		)

		err = os.Rename(oldPath, newPath)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("renamed", oldPath, "to", newPath)

		generateSizes(newBase, newPath)
	}
}

// this will generate a subset of the icons with a different imgType
// call after generateIcons, the image repo needs to be present
func generateAdditionalIcons() {

	// image name to type
	var subset = map[string]string{
		"cloud_upload":   "outline",
		"cloud_download": "outline",
		"contact_page":   "outline",
	}

	files, err := ioutil.ReadDir("/tmp/icons/png/black")
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {

		// only process files included in the subset
		if imgType, ok := subset[f.Name()]; ok {
			fmt.Println(f.Name())

			var (
				oldPath = filepath.Join("/tmp", "icons", "png", "black", filepath.Base(f.Name()), imgType+"-4x.png")
				newBase = filepath.Join("/tmp", "icons", "renamed", filepath.Base(f.Name())+"_"+imgType)
				newPath = newBase + ".png"
			)

			err = os.Rename(oldPath, newPath)
			if err != nil {
				log.Fatal(err)
			}

			fmt.Println("renamed", oldPath, "to", newPath)

			generateSizes(newBase, newPath)
		}
	}
}

func generateSizes(newBase string, newPath string) {
	data, err := ioutil.ReadFile(newPath)
	if err != nil {
		log.Fatal(err)
	}

	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		log.Fatal(err)
	}

	fXML, err := os.Create(newBase + ".xml")
	if err != nil {
		log.Fatal(err)
	}

	_, err = fXML.WriteString(icon)
	if err != nil {
		log.Fatal(err)
	}

	err = fXML.Close()
	if err != nil {
		log.Fatal(err)
	}

	for _, size := range []uint{16, 24, 32, 48, 96} {
		newImage := resize.Resize(size, size, img, resize.Lanczos3)

		f, errCreate := os.Create(newBase + strconv.Itoa(int(size)) + ".png")
		if errCreate != nil {
			log.Fatal(errCreate)
		}

		err = png.Encode(f, newImage)
		if err != nil {
			log.Fatal(err)
		}

		err = f.Close()
		if err != nil {
			log.Fatal(err)
		}
	}
}

func generateAuditRecordIcon(text string) {
	const size = 96

	im, err := gg.LoadPNG("/tmp/icons/renamed/check_box_outline_blank.png")
	if err != nil {
		log.Fatal(err)
	}

	dc := gg.NewContext(size, size)
	// dc.SetRGB(1, 1, 1)
	dc.Clear()
	dc.SetRGB(0, 0, 0)

	var fontSize float64

	switch {
	case len(text) > 12:
		fontSize = 8
	case len(text) > 10:
		fontSize = 11
	case len(text) > 8:
		fontSize = 12
	case len(text) > 6:
		fontSize = 13
	default:
		fontSize = 15
	}

	if err = dc.LoadFontFace(filepath.Join("Roboto", "Roboto-Black.ttf"), fontSize); err != nil {
		panic(err)
	}

	// dc.DrawRoundedRectangle(0, 0, 512, 512, 0)
	dc.DrawImage(im, 0, 0)
	// dc.DrawStringWrapped(text, size/2, size/2, 0.5, 0.5, 80, 1, 0)

	if strings.Contains(text, "ICMPv6") {
		dc.DrawStringAnchored("ICMPv6", size/2, size/2, 0.5, 0.5)
		dc.DrawStringAnchored(strings.TrimPrefix(text, "ICMPv6"), size/2, size/2, 0.5, 1.5)
	} else {
		dc.DrawStringAnchored(text, size/2, size/2, 0.5, 0.5)
	}

	dc.Clip()

	// not joking, Maltego fails to render images with this name
	if text == "Vulnerability" {
		text = "Vuln"
	}

	var (
		imgBase = filepath.Join("/tmp", "icons", "renamed", text)
		imgPath = imgBase + ".png"
	)

	// for testing:
	// imgBase = filepath.Join("/tmp", "icons", "V2", text)
	// imgPath = imgBase + ".png"
	// os.MkdirAll(filepath.Dir(imgBase), 0700)

	err = dc.SavePNG(imgPath)
	if err != nil {
		log.Fatal(err)
	}

	generateSizes(imgBase, imgPath)
}
