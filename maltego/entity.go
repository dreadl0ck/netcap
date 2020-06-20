package maltego

import (
	"archive/zip"
	"encoding/xml"
	"fmt"
	"github.com/dreadl0ck/netcap/utils"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

const (
	ident = "Netcap"
	netcapPrefix = "netcap."
	propsPrefix = "properties."
)

type XMLEntity struct {
	XMLName xml.Name `xml:"MaltegoEntity"`
	ID      string   `xml:"id,attr"`

	DisplayName       string `xml:"displayName,attr"`
	DisplayNamePlural string `xml:"displayNamePlural,attr"`
	Description       string `xml:"description,attr"`
	Category          string `xml:"category,attr"`

	SmallIconResource string `xml:"smallIconResource,attr"`
	LargeIconResource string `xml:"largeIconResource,attr"`

	AllowedRoot     bool             `xml:"allowedRoot,attr"`
	ConversionOrder string           `xml:"conversionOrder,attr"`
	Visible         bool             `xml:"visible,attr"`

	Entities        *BaseEntities `xml:"BaseEntities,omitempty"`
	Properties      EntityProperties `xml:"Properties"`
}

//<BaseEntities>
//<BaseEntity>netcap.IPAddr</BaseEntity>
//</BaseEntities>
type BaseEntities struct {
	Text  string `xml:",chardata"`
	Entities []BaseEntity
}

type BaseEntity struct {
	Text         string   `xml:",chardata"`
}

type EntityProperties struct {
	XMLName      xml.Name `xml:"Properties"`
	Text         string   `xml:",chardata"`
	Value        string   `xml:"value,attr"`
	DisplayValue string   `xml:"displayValue,attr"`
	Groups       string   `xml:"Groups"`
	Fields       Fields   `xml:"Fields"`
}

type Fields struct {
	Text  string `xml:",chardata"`
	Items []PropertyField
}

type PropertyField struct {
	XMLName     xml.Name `xml:"Field"`
	Text        string   `xml:",chardata"`
	Name        string   `xml:"name,attr"`
	Type        string   `xml:"type,attr"`
	Nullable    bool     `xml:"nullable,attr"`
	Hidden      bool     `xml:"hidden,attr"`
	Readonly    bool     `xml:"readonly,attr"`
	Description string   `xml:"description,attr"`
	DisplayName string   `xml:"displayName,attr"`
	SampleValue string   `xml:"SampleValue"`
}

type EntityCoreInfo struct {
	Name        string
	Icon        string
	Description string
	Parent      string
	// Fields string TODO: extra fields
}

func newEntity(entName string, imgName string, description string, parent string, fields ...PropertyField) XMLEntity {

	if !strings.Contains(imgName, "/") {
		imgName = ident + "/" + imgName
	}

	var (
		name = netcapPrefix + entName
		ent = XMLEntity{
			ID:                name,
			DisplayName:       entName,
			DisplayNamePlural: utils.Pluralize(entName),
			Description:       description,
			Category:          ident,
			SmallIconResource: imgName,
			LargeIconResource: imgName,
			AllowedRoot:       true,
			ConversionOrder:   "2147483647",
			Visible:           true,
			Properties: EntityProperties{
				XMLName:      xml.Name{},
				Text:         "",
				Value:        propsPrefix + strings.ToLower(entName),
				DisplayValue: propsPrefix + strings.ToLower(entName),
				Fields: Fields{
					Text: "",
					Items: []PropertyField{
						{
							Name:        propsPrefix + strings.ToLower(entName),
							Type:        "string",
							Nullable:    true,
							Hidden:      false,
							Readonly:    false,
							Description: "",
							DisplayName: entName,
							SampleValue: "-",
						},
					},
				},
			},
		}
	)

	if len(fields) > 0 {
		ent.Properties.Fields.Items = append(ent.Properties.Fields.Items, fields...)
	}

	if len(parent) > 0 {
		ent.Entities = &BaseEntities{
			Entities: []BaseEntity{
				{
					Text: parent,
				},
			},
		}
	}

	return ent
}

func newStringField(name string) PropertyField {
	return PropertyField{
		Name:        strings.ToLower(name),
		Type:        "string",
		Nullable:    true,
		Hidden:      false,
		Readonly:    false,
		Description: "",
		DisplayName: strings.Title(name),
		SampleValue: "",
	}
}

func genEntity(entName string, imgName string, description string, parent string, fields ...PropertyField) {

	// not joking, Maltego fails to render images with this name
	if imgName == "Vulnerability" {
		imgName = "Vuln"
	}

	var (
		name = netcapPrefix + entName
		ent = newEntity(entName, imgName, description, parent, fields...)
	)

	data, err := xml.MarshalIndent(ent, "", " ")
	if err != nil {
		log.Fatal(err)
	}

	f, err := os.Create(filepath.Join("entities", "Entities", name + ".entity"))
	if err != nil {
		log.Fatal(err)
	}

	_, err = f.Write(data)
	if err != nil {
		log.Fatal(err)
	}

	err = f.Close()
	if err != nil {
		log.Fatal(err)
	}

	// add icon files
	os.MkdirAll(filepath.Join("entities", "Icons", ident), 0700)
	copyFile(
		filepath.Join("/tmp", "icons", "renamed", imgName + ".xml"),
		filepath.Join("entities", "Icons", ident, imgName + ".xml"),
	)

	var (
		base = filepath.Join("/tmp", "icons", "renamed", imgName)
		dstBase = filepath.Join("entities", "Icons", ident, imgName)
	)

	copyFile(base + "16.png", dstBase + ".png")
	copyFile(base + "24.png", dstBase + "24.png")
	copyFile(base + "32.png", dstBase + "32.png")
	copyFile(base + "48.png", dstBase + "48.png")
	copyFile(base + "96.png", dstBase + "96.png")
}

// copyFile the source file contents to destination
// file attributes wont be copied and an existing file will be overwritten
func copyFile(src, dst string) {

	in, err := os.Open(src)
	if err != nil {
		log.Fatal(err)
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		log.Fatal(err)
	}

	err = out.Close()
	if err != nil {
		log.Fatal(err)
	}
}

// Directory structure:
// .
// ├── Entities
// │   ├── ...
// │   └── netcap.VulnerabilityAuditRecords.entity
// ├── EntityCategories
// │   └── netcap.category
// ├── Icons
// │   └── Netcap
// │       ├── sim_card_alert.png
// │       ├── sim_card_alert.xml
// │       ├── sim_card_alert24.png
// │       ├── sim_card_alert32.png
// │       ├── sim_card_alert48.png
// │       └── sim_card_alert96.png
// └── version.properties
func genEntityArchive() {

	// clean
	os.RemoveAll("entities")

	// create directories
	os.MkdirAll("entities/Entities", 0700)
	os.MkdirAll("entities/EntityCategories", 0700)
	os.MkdirAll("entities/Icons", 0700)

	fVersion, err := os.Create("entities/version.properties")
	if err != nil {
		log.Fatal(err)
	}
	defer fVersion.Close()

	fCategory, err := os.Create("entities/EntityCategories/netcap.category")
	if err != nil {
		log.Fatal(err)
	}
	defer fCategory.Close()

	fVersion.WriteString(`#
#Sat Jun 13 21:48:54 CEST 2020
maltego.client.version=4.2.11.13104
maltego.client.subtitle=
maltego.pandora.version=1.4.2
maltego.client.name=Maltego Classic Eval
maltego.mtz.version=1.0
maltego.graph.version=1.2`)

	fCategory.WriteString("<EntityCategory name=\"Netcap\"/>")

	fmt.Println("generated archive")
}

func packEntityArchive() {

	fmt.Println("packing archive")

	// zip and rename to: entities.mtz
	f, err := os.Create("entities.mtz")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	w := zip.NewWriter(f)

	// add files to the archive
	addFiles(w, "entities", "")

	err = w.Flush()
	if err != nil {
		log.Fatal(err)
	}
	err = w.Close()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("packed archive")
}

func addFiles(wr *zip.Writer, basePath, baseInZip string) {

	files, err := ioutil.ReadDir(basePath)
	if err != nil {
		fmt.Println(err)
	}

	for _, file := range files {

		path := filepath.Join(basePath, file.Name())
		fmt.Println(path)

		if !file.IsDir() {
			data, err := ioutil.ReadFile(path)
			if err != nil {
				fmt.Println(err)
			}

			// add files to the archive
			f, err := wr.Create(filepath.Join(baseInZip, file.Name()))
			if err != nil {
				log.Fatal(err)
			}
			_, err = f.Write(data)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			newBase := filepath.Join(basePath, file.Name(), "/")
			fmt.Println("adding sub directory: " + newBase)
			addFiles(wr, newBase, filepath.Join(baseInZip, file.Name(), "/"))
		}
	}
}
