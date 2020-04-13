/* Maltego library for Go
 * glenn@sensepost.com // @glennzw
 *
 * Implemented almost verbatim from the Maltego.py library
 * Adjusted by Philipp Mieden for the NETCAP project.
 *
 */

// Implements primitives for maltego transformations over netcap audit records
package maltego

import (
	"encoding/xml"
	"log"
	"strconv"
	"strings"
)

//Set constants
const (
	BOOKMARK_COLOR_NONE   = "-1"
	BOOKMARK_COLOR_BLUE   = "0"
	BOOKMARK_COLOR_GREEN  = "1"
	BOOKMARK_COLOR_YELLOW = "2"
	BOOKMARK_COLOR_ORANGE = "3"
	BOOKMARK_COLOR_RED    = "4"

	LINK_STYLE_NORMAL  = "0"
	LINK_STYLE_DASHED  = "1"
	LINK_STYLE_DOTTED  = "2"
	LINK_STYLE_DASHDOT = "3"

	UIM_FATAL   = "FatalError"
	UIM_PARTIAL = "PartialError"
	UIM_INFORM  = "Inform"
	UIM_DEBUG   = "Debug"
)

func GetThicknessInterval(val, min, max uint64) int {

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

func GetThickness(val, min, max uint64) int {

	if min == max {
		min = 0
	}

	delta := max - min

	//log.Println("delta=", delta, "float64(delta)*0.01 = ", float64(delta)*0.01)
	//log.Println("delta=", delta, "float64(delta)*0.1 = ", float64(delta)*0.1)
	//log.Println("delta=", delta, "float64(delta)*0.5 = ", float64(delta)*0.5)
	//log.Println("delta=", delta, "float64(delta)*1 = ", float64(delta)*1)
	//log.Println("delta=", delta, "float64(delta)*2 = ", float64(delta)*2)

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

type MaltegoEntityObj struct {
	entityType         string
	value              string
	iconURL            string
	weight             int
	displayInformation [][]string
	AdditionalFields   [][]string
}

//Constructor for MaltegoEntityObj
func MaltegoEntity(eT string, eV string) *MaltegoEntityObj {
	return &MaltegoEntityObj{entityType: eT, value: eV, weight: 100}
}

/*Next we handle the MalteoTransform class from Python*/
type MaltegoTransform struct {
	entities   []*MaltegoEntityObj
	exceptions [][]string
	UIMessages [][]string
}

func (m *MaltegoTransform) AddEntity(enType, enValue string) *MaltegoEntityObj {
	//me := MaltegoEntity(enType, enValue) //Not too sure why this doesn't work
	me := &MaltegoEntityObj{entityType: enType, value: enValue, weight: 100}
	m.entities = append(m.entities, me)
	return me
}

func (m *MaltegoTransform) AddUIMessage(message, messageType string) {
	msg := []string{messageType, message}
	m.UIMessages = append(m.UIMessages, msg)
}

func (m *MaltegoTransform) AddException(exceptionString, code string) {
	exc := []string{exceptionString, code}
	m.exceptions = append(m.exceptions, exc)
}

func (m *MaltegoTransform) ReturnOutput() string {
	r := "<MaltegoMessage>\n"
	r += "<MaltegoTransformResponseMessage>\n"
	r += "<Entities>\n"
	for _, e := range m.entities {
		r += e.ReturnEntity()
	}
	r += "</Entities>\n"
	r += "<UIMessages>\n"
	for _, e := range m.UIMessages {
		mType, mVal := e[0], e[1]
		r += "<UIMessage MessageType=\"" + mType + "\">" + mVal + "</UIMessage>\n"
	}
	r += "</UIMessages>\n"
	r += "</MaltegoTransformResponseMessage>\n"
	r += "</MaltegoMessage>\n"
	return r
}

func (m *MaltegoTransform) ThrowExceptions() string {
	r := "<MaltegoMessage>\n"
	r += "<MaltegoTransformExceptionMessage>\n"
	r += "<Exceptions>\n"
	for _, e := range m.exceptions {
		code, ex := e[0], e[1]
		r += "<Exception code='" + code + "'>" + ex + "</Exception>\n"
	}
	r += "</Exceptions>\n"
	r += "</MaltegoTransformExceptionMessage>\n"
	r += "</MaltegoMessage>\n"
	return r
}

//2. Setter and Getter functions for MaltegoEntityObjs
func (m *MaltegoEntityObj) SetType(eT string) {
	m.entityType = eT
}

func (m *MaltegoEntityObj) SetValue(eV string) {
	m.value = eV
}

func (m *MaltegoEntityObj) SetWeight(w int) {
	m.weight = w
}

func (m *MaltegoEntityObj) SetIconURL(iU string) {
	m.iconURL = iU
}

func (m *MaltegoEntityObj) AddProperty(fieldName, displayName, matchingRule, value string) {
	prop := []string{fieldName, displayName, matchingRule, value}
	m.AdditionalFields = append(m.AdditionalFields, prop)
}

func (m *MaltegoEntityObj) AddDisplayInformation(di, dl string) {
	info := []string{dl, di}
	m.displayInformation = append(m.displayInformation, info)
}

func (m *MaltegoEntityObj) SetLinkColor(color string) {
	m.AddProperty("link#maltego.link.color", "LinkColor", "", color)
}

func (m *MaltegoEntityObj) SetLinkStyle(style string) {
	m.AddProperty("link#maltego.link.style", "LinkStyle", "", style)
}

func (m *MaltegoEntityObj) SetLinkThickness(thick int) {
	thickInt := strconv.Itoa(thick)
	m.AddProperty("link#maltego.link.thickness", "LinkThickness", "", thickInt)
}

func (m *MaltegoEntityObj) SetLinkLabel(label string) {
	m.AddProperty("link#maltego.link.label", "Label", "", label)
}

func (m *MaltegoEntityObj) SetBookmark(bookmark string) {
	m.AddProperty("bookmark#", "Bookmark", "", bookmark)
}

func (m *MaltegoEntityObj) SetNote(note string) {
	m.AddProperty("notes#", "Notes", "", note)
}

func (m *MaltegoEntityObj) SetLinkDirection(dir string) {
	m.AddProperty("link#maltego.link.direction", "Direction", "loose", dir)
	//me.addProperty('link#maltego.link.direction','link#maltego.link.direction','loose','output-to-input')
}

func (m *MaltegoEntityObj) ReturnEntity() string {
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

/***/

/* 3. MaltegoMsg Python class implementation */

//Here we have the XML structs to map to
type MaltegoMessage struct {
	XMLName xml.Name `xml:"MaltegoMessage"`
	MTRM    MaltegoTransformRequestMessage
}

type MaltegoTransformRequestMessage struct {
	XMLName  xml.Name `xml:"MaltegoTransformRequestMessage"`
	Entities Entities `xml:"Entities"`
	Limits   Limit    `xml:"Limits"`
}

type Entities struct {
	EntityList []Entity `xml:"Entity"`
}

type Entity struct {
	//Text string `xml:",chardata"`
	XMLName xml.Name         `xml:"Entity"`
	Type    string           `xml:"Type,attr"`
	AddF    AdditionalFields `xml:"AdditionalFields"`
	Value   string           `xml:"Value"`
	Weight  string           `xml:"Weight"`
}

type AdditionalFields struct {
	FieldList []Field `xml:"Field"`
}

type Field struct {
	FieldValue  string `xml:",chardata"`
	FieldName   string `xml:"Name,attr"`
	DisplayName string `xml:"DisplayName,attr"`
}

type Limit struct {
	XMLName   xml.Name `xml:"Limits"`
	HardLimit string   `xml:"HardLimit,attr"`
	SoftLimit string   `xml:"SoftLimit,attr"`
}

//End XML structs mapping

//Code to parse Maltego XML Input
type MaltegoMsgObj struct {
	Value             string
	Weight            string
	Slider            string //Forgot to implement the XML for this
	Type              string
	Properties        map[string]string
	TransformSettings map[string]string //Forgot to implement the XML for this
}

//Constructor for MaltegoMsg
func MaltegoMsg(MaltegoXML string) MaltegoMsgObj {

	v := MaltegoMessage{}
	err := xml.Unmarshal([]byte(MaltegoXML), &v)
	if err != nil {
		panic(err)
	}

	//Copying the Python code it seems there can be only one Entity Value in
	// the entity list. So we just hardcode the [0] index here.
	Value := v.MTRM.Entities.EntityList[0].Value
	Weight := v.MTRM.Entities.EntityList[0].Weight
	Type := v.MTRM.Entities.EntityList[0].Type
	Slider := v.MTRM.Limits.HardLimit
	FieldList := v.MTRM.Entities.EntityList[0].AddF.FieldList

	Props := make(map[string]string)
	for _, f := range FieldList {
		Props[f.FieldName] = f.FieldValue
	}

	m := MaltegoMsgObj{Value: Value, Weight: Weight, Type: Type, Slider: Slider, Properties: Props}
	return m
}

func (m *MaltegoMsgObj) GetProperty(p string) string {
	return m.Properties[p]
}

func (m *MaltegoMsgObj) GetTransformSetting(t string) string {
	return m.TransformSettings[t]
}

/* 4. Handle local transform from stdin */
type LocalTransform struct {
	Value  string
	Values map[string]string
}

func ParseLocalArguments(args []string) LocalTransform {
	if len(args) < 3 {
		log.Fatal("need at least 3 arguments, got ", len(args), ": ", args)
	}
	Value := args[2]
	Vals := make(map[string]string)
	if len(args) > 3 {
		vars := strings.Split(args[3], "#")
		for _, x := range vars {
			kv := strings.Split(x, "=")
			if len(kv) == 2 {
				Vals[kv[0]] = kv[1]
			} else {
				Vals[kv[0]] = ""
			}
		}
	}
	return LocalTransform{Value: Value, Values: Vals}
}
