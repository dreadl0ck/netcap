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
	"encoding/xml"
	"errors"
	"fmt"
	"image"
	"image/png"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/fogleman/gg"
	"github.com/go-git/go-git/v5"
	svgcheck "github.com/h2non/go-is-svg"
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

func TestGenerateAuditRecordIconsSVG(t *testing.T) {
	generateIconsSVG()
	generateAdditionalIconsSVG()

	decoder.ApplyActionToCustomDecoders(func(d decoder.CustomDecoderAPI) {
		fmt.Println(d.GetName())
		generateAuditRecordIconSVG(d.GetName())
	})

	decoder.ApplyActionToGoPacketDecoders(func(e *decoder.GoPacketDecoder) {
		name := strings.ReplaceAll(e.Layer.String(), "/", "")
		fmt.Println(name)
		generateAuditRecordIconSVG(name)
	})
}

// Utils

const (
	svgIconPath = "/tmp/icons/material-icons"
	pngIconPath = "/tmp/icons/material-icons-png"
)

func cloneIcons() {
	_ = os.RemoveAll(pngIconPath)

	_, err := git.PlainClone(pngIconPath, false, &git.CloneOptions{
		URL:      "https://github.com/dreadl0ck/material-icons-png.git",
		Progress: os.Stdout,
	})

	if err != nil && !errors.Is(err, git.ErrRepositoryAlreadyExists) {
		log.Fatal(err)
	}

	fmt.Println("cloned icon repository to", pngIconPath)
}

func generateIcons() {
	cloneIcons()

	// rename icons
	_ = os.Mkdir(filepath.Join(pngIconPath, "renamed"), 0o700)

	files, err := ioutil.ReadDir(filepath.Join(pngIconPath, "png", "black"))
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		// fmt.Println(f.Name())

		var (
			oldPath = filepath.Join(pngIconPath, "png", "black", filepath.Base(f.Name()), "twotone-4x.png")
			newBase = filepath.Join(pngIconPath, "renamed", filepath.Base(f.Name()))
			newPath = newBase + ".png"
		)

		err = os.Rename(oldPath, newPath)
		if err != nil {
			log.Fatal(err)
		}

		// fmt.Println("renamed", oldPath, "to", newPath)

		generateSizes(newBase, newPath)
	}
}

func cloneIconsSVG() {
	_ = os.RemoveAll(svgIconPath)

	_, err := git.PlainClone(svgIconPath, false, &git.CloneOptions{
		URL:      "https://github.com/dreadl0ck/material-icons.git",
		Progress: os.Stdout,
	})

	if err != nil && !errors.Is(err, git.ErrRepositoryAlreadyExists) {
		log.Fatal(err)
	}

	fmt.Println("cloned icon repository to", svgIconPath)
}

func generateIconsSVG() {
	cloneIconsSVG()

	// rename icons
	_ = os.Mkdir(filepath.Join(svgIconPath, "renamed"), 0o700)

	files, err := ioutil.ReadDir(filepath.Join(svgIconPath, "svg"))
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		// fmt.Println(f.Name())

		var (
			oldPath = filepath.Join(svgIconPath, "svg", filepath.Base(f.Name()), "twotone.svg")
			newBase = filepath.Join(svgIconPath, "renamed", filepath.Base(f.Name()))
			newPath = newBase + ".svg"
		)

		err = os.Rename(oldPath, newPath)
		if err != nil {
			log.Fatal(err)
		}

		// fmt.Println("renamed", oldPath, "to", newPath)

		if colorNames, ok := coloredIcons[f.Name()]; ok {
			for _, c := range colorNames {
				generateSizesSVG(newBase, newPath, c)
			}
		} else {
			generateSizesSVG(newBase, newPath, "black")
		}
	}
}

// image name to type
var subset = map[string]string{
	"cloud_upload":   "outline",
	"cloud_download": "outline",
	"contact_page":   "outline",
}

// image name to colors
var coloredIcons = map[string][]string{
	"insert_drive_file": colors,
}

var colors = []string{
	"indianred",
	"aquamarine",
	"orangered",
	"crimson",
	"red",
	"coral",
	"slateblue",
	"rebeccapurple",
	"orange",
	"gold",
	"green",
	"thistle",
	"magenta",
	"blueviolet",
	"navy",
	"tomato",
	"indigo",
	"lawngreen",
	"salmon",
	"seagreen",
	"olivedrab",
	"powderblue",
	"olive",
	"dodgerblue",
	"firebrick",
	"steelblue",
	"aqua",
	"skyblue",
	"teal",
	"blue",
	"burlywood",
	"tan",
	"turquoise",
	"rosybrown",
	"sandybrown",
	"goldenrod",
	"peru",
	"royalblue",
	"deepskyblue",
	"chocolate",
	"saddlebrown",
	"sienna",
	"cadetblue",
	"brown",
	"maroon",
	"midnightblue",
}

// this will generate a subset of the icons with a different imgType
// call after generateIcons, the image repo needs to be present
func generateAdditionalIcons() {
	files, err := ioutil.ReadDir(filepath.Join(pngIconPath, "png", "black"))
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		// only process files included in the subset
		if imgType, ok := subset[f.Name()]; ok {
			fmt.Println(f.Name())

			var (
				oldPath = filepath.Join(pngIconPath, "png", "black", filepath.Base(f.Name()), imgType+"-4x.png")
				newBase = filepath.Join(pngIconPath, "renamed", filepath.Base(f.Name())+"_"+imgType)
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

func generateAdditionalIconsSVG() {
	files, err := ioutil.ReadDir(filepath.Join(svgIconPath, "svg"))
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		// only process files included in the subset
		if imgType, ok := subset[f.Name()]; ok {
			// fmt.Println(f.Name())

			var (
				oldPath = filepath.Join(svgIconPath, "svg", filepath.Base(f.Name()), imgType+".svg")
				newBase = filepath.Join(svgIconPath, "renamed", filepath.Base(f.Name())+"_"+imgType)
				newPath = newBase + ".svg"
			)

			err = os.Rename(oldPath, newPath)
			if err != nil {
				log.Fatal(err)
			}

			// fmt.Println("renamed", oldPath, "to", newPath)

			generateSizesSVG(newBase, newPath, "black")
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

	createXMLIconFile(newBase)

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

type materialIconSVG struct {
	XMLName xml.Name `xml:"svg"`

	Xmlns   string `xml:"xmlns,attr"`
	Width   string `xml:"width,attr"`
	Height  string `xml:"height,attr"`
	ViewBox string `xml:"viewBox,attr"`
	Paths   []Path `xml:"path"`

	Rect *struct {
		Text        string `xml:",chardata"`
		X           string `xml:"x,attr"`
		Y           string `xml:"y,attr"`
		Width       string `xml:"width,attr"`
		Height      string `xml:"height,attr"`
		Stroke      string `xml:"stroke,attr"`
		StrokeWidth string `xml:"stroke-width,attr"`
		Fill        string `xml:"fill,attr"`
	} `xml:"rect,omitempty"`

	Text *struct {
		Text             string `xml:",chardata"`
		X                string `xml:"x,attr"`
		Y                string `xml:"y,attr"`
		DominantBaseline string `xml:"dominant-baseline,attr"`
		TextAnchor       string `xml:"text-anchor,attr"`
	} `xml:"text,omitempty"`
}

type Path struct {
	Text    string `xml:",chardata"`
	Opacity string `xml:"opacity,attr"`
	D       string `xml:"d,attr"`
	Style   string `xml:"style,attr,omitempty"`
}

func (s *materialIconSVG) resizeSVG(width, height int) {
	s.Height = strconv.Itoa(height)
	s.Width = strconv.Itoa(width)
}

func createXMLIconFile(path string) {
	// create XML info file for maltego
	fXML, err := os.Create(path + ".xml")
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
}

func generateSizesSVG(newBase string, newPath string, color string) {
	svgFile, err := os.Open(newPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return
	}
	defer svgFile.Close()

	s := new(materialIconSVG)
	if err = xml.NewDecoder(svgFile).Decode(&s); err != nil {
		fmt.Fprintf(os.Stderr, "Unable to parse (%v)\n", err)
		return
	}

	for i := range s.Paths {
		s.Paths[i].Style = "fill: " + color + ";"
	}

	if s.ViewBox == "" {
		s.ViewBox = "0 0 100 100"
	}

	createXMLIconFile(newBase + "_" + color)

	for _, size := range []int{16, 24, 32, 48, 96} {

		s.resizeSVG(size, size)
		f, errCreate := os.Create(newBase + "_" + color + strconv.Itoa(size) + ".svg")
		if errCreate != nil {
			log.Fatal(errCreate)
		}

		var buf bytes.Buffer

		if err = xml.NewEncoder(io.MultiWriter(f, &buf)).Encode(s); err != nil {
			fmt.Fprintf(os.Stderr, "Unable to encode (%v)\n", err)
			return
		}

		err = f.Close()
		if err != nil {
			log.Fatal(err)
		}

		if !svgcheck.Is(buf.Bytes()) {
			log.Fatal("invalid SVG image generated:", f.Name())
		}
	}
}

func generateAuditRecordIcon(text string) {
	const size = 96

	im, err := gg.LoadPNG("/tmp/icons/material-icons-png/renamed/check_box_outline_blank.png")
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

	var (
		imgBase = filepath.Join("/tmp", "icons", "material-icons-png", "renamed", text)
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

func generateAuditRecordIconSVG(text string) {
	var (
		size = 96
		x    = `<svg version="1.1" xmlns="http://www.w3.org/2000/svg" width="` + strconv.Itoa(size) + `" height="` + strconv.Itoa(size) + `">
<rect x="0" y="0" width="` + strconv.Itoa(size) + `" height="` + strconv.Itoa(size) + `" stroke="red" stroke-width="3px" fill="white"/>
<text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle">` + text + `</text>
</svg>`
	)

	var (
		imgBase = filepath.Join("/tmp", "icons", "material-icons", "renamed", text)
		imgPath = imgBase + ".svg"
	)

	file, err := os.Create(imgPath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	_, err = file.WriteString(x)
	if err != nil {
		log.Fatal(err)
	}

	if !svgcheck.Is([]byte(x)) {
		log.Fatal("invalid SVG", x)
	}

	generateSizesSVG(imgBase, imgPath, "black")
}
