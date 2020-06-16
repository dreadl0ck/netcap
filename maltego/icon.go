package maltego

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/go-git/go-git/v5"
	"github.com/golang/freetype"
	"github.com/nfnt/resize"
	"golang.org/x/image/font"
	"golang.org/x/image/math/fixed"
	"image"
	"image/draw"
	"image/png"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Icons/Netcap/sim_card_alert.xml
var Icon = `<Icon>
<Aliases/>
</Icon>`

func generateIcons() {

	os.RemoveAll("/tmp/icons")
	_, err := git.PlainClone("/tmp/icons", false, &git.CloneOptions{
		URL:      "https://github.com/material-icons/material-icons-png.git",
		Progress: os.Stdout,
	})
	if err != nil && err != git.ErrRepositoryAlreadyExists {
		log.Fatal(err)
	}

	fmt.Println("cloned icon repository to", "/tmp/icons")

	// rename icons
	os.Mkdir("/tmp/icons/renamed", 0700)

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

		_, err = fXML.WriteString(Icon)
		if err != nil {
			log.Fatal(err)
		}

		err = fXML.Close()
		if err != nil {
			log.Fatal(err)
		}

		for _, size := range []uint{16, 24, 32, 48, 96} {

			newImage := resize.Resize(size, size, img, resize.Lanczos3)
			f, err := os.Create(newBase + strconv.Itoa(int(size)) + ".png")
			if err != nil {
				log.Fatal(err)
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
}

var text = []string{
	"TLS",
	"HTTP",
	"MODBUS",
	"DeviceProfile",
	"SSH",
	"Credentials",
	"Service",
	"Software",
	"File",
	"HTTP",
	"DNS",
	"POP3",
	"SMTP",
	"DHCPv4",
	"DHCPv6",
	"Flow",
	"Vulnerability",
	"Exploit",
}

// TODO: integrate into logic in entity_test.go and invoke for each audit record name
func generateAuditRecordIcons() {

	var (
		dpi      = 72.0
		fontfile = "Roboto/Roboto-Black.ttf"
		hinting  = "none"
		size     = 33.0
		spacing  = 1.0
		wonb     = false
	)

	// Read the font data.
	fontBytes, err := ioutil.ReadFile(fontfile)
	if err != nil {
		log.Println(err)
		return
	}
	f, err := freetype.ParseFont(fontBytes)
	if err != nil {
		log.Println(err)
		return
	}

	for _, t := range text {

		// ensure all chars are the same width
		t = strings.ToUpper(t)

		// Initialize the context.
		fg, bg := image.Black, image.Transparent
		if wonb {
			fg, bg = image.White, image.Black
		}
		rgba := image.NewRGBA(image.Rect(0, 0, 96, 96))
		draw.Draw(rgba, rgba.Bounds(), bg, image.ZP, draw.Src)
		c := freetype.NewContext()
		c.SetDPI(dpi)
		c.SetFont(f)

		var fSize float64
		fSize = size

		fmt.Println(t, len(t))

		var pt fixed.Point26_6
		switch len(t) {
		case 12,13:
			fSize = 11
			pt = freetype.Pt(3, 48+int(c.PointToFixed(fSize)>>6))
		case 9,10,11:
			fSize = 13
			pt = freetype.Pt(3, 45+int(c.PointToFixed(fSize)>>6))
		case 8:
			fSize = 17
			pt = freetype.Pt(3, 38+int(c.PointToFixed(fSize)>>6))
		case 5,6,7:
			fSize = 20
			pt = freetype.Pt(5, 33+int(c.PointToFixed(fSize)>>6))
		case 4:
			pt = freetype.Pt(3, 27+int(c.PointToFixed(fSize)>>6))
		case 3:
			pt = freetype.Pt(15, 27+int(c.PointToFixed(fSize)>>6))
		default:
			pt = freetype.Pt(3, 27+int(c.PointToFixed(fSize)>>6))
		}

		c.SetFontSize(fSize)
		c.SetClip(rgba.Bounds())
		c.SetDst(rgba)
		c.SetSrc(fg)
		switch hinting {
		default:
			c.SetHinting(font.HintingNone)
		case "full":
			c.SetHinting(font.HintingFull)
		}

		// Draw the text.
		_, err = c.DrawString(t, pt)
		if err != nil {
			log.Println(err)
			return
		}

		pt.Y += c.PointToFixed(fSize * spacing)

		// Save that RGBA image to disk.
		outFile, err := os.Create(t+".png")
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
		defer outFile.Close()

		b := bufio.NewWriter(outFile)
		err = png.Encode(b, rgba)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
		err = b.Flush()
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
		fmt.Println("Wrote " + t + ".png OK")
	}
}