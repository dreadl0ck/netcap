/* Maltego library for Go
 * glenn@sensepost.com // @glennzw
 *
 * Implemented almost verbatim from the Maltego.py library
 * Adjusted by Philipp Mieden for the NETCAP project.
 *
 */

// Package maltego Implements primitives for maltego transformations over netcap audit records
package maltego

import (
	"encoding/xml"
	"log"
	"strconv"
	"strings"
)

// set constants
//goland:noinspection GoUnusedConst,GoUnnecessarilyExportConstant
const (
	BookMarkColorNone   = "-1"
	BookMarkColorBlue   = "0"
	BookMarkColorGreen  = "1"
	BookMarkColorYellow = "2"
	BookMarkColorOrange = "3"
	BookMarkColorRed    = "4"

	LinkStyleNormal  = "0"
	LinkStyleDashed  = "1"
	LinkStyleDotted  = "2"
	LinkStyleDashdot = "3"

	UIMessageFatal        = "FatalError"
	UIMessagePartialError = "PartialError"
	UIMessageInform       = "Inform"
	UIMessageDebug        = "Debug"
)

func getThicknessInterval(val, min, max uint64) int {
	if min == max {
		min = 0
	}

	interval := (max - min) / 5

	switch {
	case val <= interval:
		return 1
	case val <= interval*2:
		return 2
	case val <= interval*3:
		return 3
	case val <= interval*4:
		return 4
	case val <= interval*5:
		return 5
	default: // bigger than interval*5
		return 5
	}
}

// Sets the progressbar in Maltego
// this is documented in the old versions of the Maltego manual
// but does not seem to work with the current version
//func (m *MaltegoTransform) PrintProgress(percentage int) {
//
//	if percentage < 0 || percentage > 100 {
//		fmt.Println("invalid percentage value:", percentage)
//		return
//	}
//
//	os.Stderr.WriteString("%" + strconv.Itoa(percentage) + "\n")
//}

// GetThickness can be used to calculate the line thickness.
func GetThickness(val, min, max uint64) int {
	if min == max {
		min = 0
	}

	delta := max - min

	// log.Println("delta=", delta, "float64(delta)*0.01 = ", float64(delta)*0.01)
	// log.Println("delta=", delta, "float64(delta)*0.1 = ", float64(delta)*0.1)
	// log.Println("delta=", delta, "float64(delta)*0.5 = ", float64(delta)*0.5)
	// log.Println("delta=", delta, "float64(delta)*1 = ", float64(delta)*1)
	// log.Println("delta=", delta, "float64(delta)*2 = ", float64(delta)*2)

	switch {
	case float64(val) <= float64(delta)*0.01:
		return 1
	case float64(val) <= float64(delta)*0.1:
		return 2
	case float64(val) <= float64(delta)*0.3:
		return 3
	case float64(val) <= float64(delta)*0.6:
		return 4
	case float64(val) <= float64(delta)*0.9:
		return 5
	default:
		return 5
	}
}

/* First we handle the MaltegoEntity conversion from Python */

// EntityObj models a Maltego entity.
type EntityObj struct {
	entityType         string
	value              string
	iconURL            string
	weight             int
	displayInformation [][]string
	AdditionalFields   [][]string
}

// Constructor for MaltegoEntityObj.
func newEntityObj(eT string, eV string) *EntityObj {
	return &EntityObj{entityType: eT, value: eV, weight: 100}
}

// Transform /*Next we handle the MalteoTransform class from Python*/.
type Transform struct {
	entities   []*EntityObj
	exceptions [][]string
	UIMessages [][]string
}

func (tr *Transform) AddEntity(enType, enValue string) *EntityObj {
	me := &EntityObj{entityType: enType, value: EscapeText(enValue), weight: 100}
	tr.entities = append(tr.entities, me)

	return me
}

func (tr *Transform) AddUIMessage(message, messageType string) {
	tr.UIMessages = append(tr.UIMessages, []string{messageType, message})
}

func (tr *Transform) addException(exceptionString, code string) {
	exc := []string{exceptionString, code}
	tr.exceptions = append(tr.exceptions, exc)
}

func (tr *Transform) ReturnOutput() string {
	r := "<MaltegoMessage>\n"
	r += "<MaltegoTransformResponseMessage>\n"
	r += "<Entities>\n"

	for _, e := range tr.entities {
		r += e.returnEntity()
	}

	r += "</Entities>\n"
	r += "<UIMessages>\n"

	for _, e := range tr.UIMessages {
		mType, mVal := e[0], e[1]
		r += "<UIMessage MessageType=\"" + mType + "\">" + mVal + "</UIMessage>\n"
	}

	r += "</UIMessages>\n"
	r += "</MaltegoTransformResponseMessage>\n"
	r += "</MaltegoMessage>\n"

	return r
}

func (tr *Transform) throwExceptions() string {
	r := "<MaltegoMessage>\n"
	r += "<MaltegoTransformExceptionMessage>\n"
	r += "<Exceptions>\n"

	for _, e := range tr.exceptions {
		code, ex := e[0], e[1]
		r += "<Exception code='" + code + "'>" + ex + "</Exception>\n"
	}

	r += "</Exceptions>\n"
	r += "</MaltegoTransformExceptionMessage>\n"
	r += "</MaltegoMessage>\n"

	return r
}

// 2. Setter and Getter functions for MaltegoEntityObjs.
func (m *EntityObj) setType(eT string) {
	m.entityType = eT
}

func (m *EntityObj) setValue(eV string) {
	m.value = eV
}

func (m *EntityObj) setWeight(w int) {
	m.weight = w
}

// SetIconURL sets the icon URL.
func (m *EntityObj) SetIconURL(iU string) {
	m.iconURL = iU
}

// AddProperty adds a property.
func (m *EntityObj) AddProperty(fieldName, displayName, matchingRule, value string) {
	prop := []string{fieldName, displayName, matchingRule, EscapeText(value)}
	m.AdditionalFields = append(m.AdditionalFields, prop)
}

// AddDisplayInformation adds display information.
func (m *EntityObj) AddDisplayInformation(di, dl string) {
	info := []string{dl, di}
	m.displayInformation = append(m.displayInformation, info)
}

func (m *EntityObj) setLinkColor(color string) {
	m.AddProperty("link#maltego.link.color", "LinkColor", "", color)
}

func (m *EntityObj) setLinkStyle(style string) {
	m.AddProperty("link#maltego.link.style", "LinkStyle", "", style)
}

// SetLinkThickness sets the link thickness.
func (m *EntityObj) SetLinkThickness(thick int) {
	thickInt := strconv.Itoa(thick)
	m.AddProperty("link#maltego.link.thickness", "LinkThickness", "", thickInt)
}

// SetLinkLabel sets the link label.
func (m *EntityObj) SetLinkLabel(label string) {
	m.AddProperty("link#maltego.link.label", "Label", "", label)
}

func (m *EntityObj) setBookmark(bookmark string) {
	m.AddProperty("bookmark#", "Bookmark", "", bookmark)
}

func (m *EntityObj) SetNote(note string) {
	m.AddProperty("notes#", "Notes", "", note)
}

func (m *EntityObj) SetLinkDirection(dir string) {
	m.AddProperty("link#maltego.link.direction", "Direction", "loose", dir)
	// me.addProperty('link#maltego.link.direction','link#maltego.link.direction','loose','output-to-input')
}

func (m *EntityObj) returnEntity() string {
	r := "<Entity Type=\"" + m.entityType + "\">\n"
	r += "<Value>" + m.value + "</Value>\n"
	r += "<Weight>" + strconv.Itoa(m.weight) + "</Weight>\n"

	if len(m.displayInformation) > 0 {
		r += "<DisplayInformation>\n"

		for _, e := range m.displayInformation {
			name_, type_ := e[0], e[1]
			r += "<Label Name=\"" + name_ + "\" Type=\"text/html\"><![CDATA[" + type_ + "]]></Label>\n"
		}

		r += "</DisplayInformation>\n"
	}

	if len(m.AdditionalFields) > 0 {
		r += "<AdditionalFields>\n"

		for _, e := range m.AdditionalFields {
			fieldName_, displayName_, matchingRule_, value_ := e[0], e[1], e[2], e[3]
			if matchingRule_ == "strict" {
				r += "<Field Name=\"" + fieldName_ + "\" DisplayName=\"" + displayName_ + "\">" + value_ + "</Field>\n"
			} else {
				r += "<Field MatchingRule=\"" + matchingRule_ + "\" Name=\"" + fieldName_ + "\" DisplayName=\"" + displayName_ + "\">" + value_ + "</Field>\n"
			}
		}

		r += "</AdditionalFields>\n"
	}

	if len(m.iconURL) > 0 {
		r += "<IconURL>" + m.iconURL + "</IconURL>\n"
	}

	r += "</Entity>"

	return r
}

/* 3. MaltegoMsg Python class implementation */

// Here we have the XML structs to map to.
type message struct {
	XMLName xml.Name `xml:"MaltegoMessage"`
	MTRM    transformRequestMessage
}

type transformRequestMessage struct {
	XMLName  xml.Name `xml:"MaltegoTransformRequestMessage"`
	Entities entities `xml:"Entities"`
	Limits   limit    `xml:"Limits"`
}

type entities struct {
	EntityList []entity `xml:"Entity"`
}

type entity struct {
	// Text string `xml:",chardata"`
	XMLName xml.Name         `xml:"Entity"`
	Type    string           `xml:"Type,attr"`
	AddF    additionalFields `xml:"AdditionalFields"`
	Value   string           `xml:"Value"`
	Weight  string           `xml:"Weight"`
}

type additionalFields struct {
	FieldList []field `xml:"Field"`
}

type field struct {
	FieldValue  string `xml:",chardata"`
	FieldName   string `xml:"Name,attr"`
	DisplayName string `xml:"DisplayName,attr"`
}

type limit struct {
	XMLName   xml.Name `xml:"Limits"`
	HardLimit string   `xml:"HardLimit,attr"`
	SoftLimit string   `xml:"SoftLimit,attr"`
}

// End XML structs mapping

// Code to parse Maltego XML Input.
type msgObj struct {
	Value             string
	Weight            string
	Slider            string // Forgot to implement the XML for this
	Type              string
	Properties        map[string]string
	TransformSettings map[string]string // Forgot to implement the XML for this
}

// Constructor for MaltegoMsg.
func msg(MaltegoXML string) msgObj {
	v := message{}

	err := xml.Unmarshal([]byte(MaltegoXML), &v)
	if err != nil {
		panic(err)
	}

	// Copying the Python code it seems there can be only one Entity Value in
	// the entity list. So we just hardcode the [0] index here.
	var (
		value     = v.MTRM.Entities.EntityList[0].Value
		weight    = v.MTRM.Entities.EntityList[0].Weight
		typ       = v.MTRM.Entities.EntityList[0].Type
		slider    = v.MTRM.Limits.HardLimit
		fieldList = v.MTRM.Entities.EntityList[0].AddF.FieldList
		props     = make(map[string]string)
	)

	for _, f := range fieldList {
		props[f.FieldName] = f.FieldValue
	}

	return msgObj{Value: value, Weight: weight, Type: typ, Slider: slider, Properties: props}
}

func (m *msgObj) getProperty(p string) string {
	return m.Properties[p]
}

func (m *msgObj) getTransformSetting(t string) string {
	return m.TransformSettings[t]
}

// LocalTransform /* 4. Handle local transform from stdin */.
type LocalTransform struct {
	Value  string
	Values map[string]string
}

// ParseLocalArguments parses the arguments supplied on the commandline.
func ParseLocalArguments(args []string) LocalTransform {
	if len(args) < 3 {
		log.Fatal("need at least 3 arguments, got ", len(args), ": ", args)
	}

	var (
		value  = args[2]
		values = make(map[string]string)
	)

	if len(args) > 3 {
		// search the remaining arguments for variables
		for _, arg := range args[3:] {
			if len(arg) > 0 {
				vars := strings.Split(arg, "#")
				for _, x := range vars {
					kv := strings.Split(x, "=")
					if len(kv) == 2 {
						values[kv[0]] = kv[1]
					} else {
						values[kv[0]] = ""
					}
				}
			}
		}
	}

	return LocalTransform{Value: value, Values: values}
}
