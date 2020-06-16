package maltego

import "encoding/xml"

// Transforms

// File: TransformRepositories/Local/netcap.ToAuditRecords.transform

// <MaltegoTransform name="netcap.ToAuditRecords" displayName="To Audit Records [NETCAP]" abstract="false" template="false" visibility="public" description="Transform PCAP file into audit records" author="Philipp Mieden" requireDisplayInfo="false">
// <TransformAdapter>com.paterva.maltego.transform.protocol.v2api.LocalTransformAdapterV2</TransformAdapter>
// <Properties>
// <Fields>
// <Property name="transform.local.command" type="string" nullable="false" hidden="false" readonly="false" description="The command to execute for this transform" popup="false" abstract="false" visibility="public" auth="false" displayName="Command line">
// <SampleValue></SampleValue>
// </Property>
// <Property name="transform.local.parameters" type="string" nullable="true" hidden="false" readonly="false" description="The parameters to pass to the transform command" popup="false" abstract="false" visibility="public" auth="false" displayName="Command parameters">
// <SampleValue></SampleValue>
// </Property>
// <Property name="transform.local.working-directory" type="string" nullable="true" hidden="false" readonly="false" description="The working directory used when invoking the executable" popup="false" abstract="false" visibility="public" auth="false" displayName="Working directory">
// <DefaultValue>/</DefaultValue>
// <SampleValue></SampleValue>
// </Property>
// <Property name="transform.local.debug" type="boolean" nullable="true" hidden="false" readonly="false" description="When this is set, the transform&apos;s text output will be printed to the output window" popup="false" abstract="false" visibility="public" auth="false" displayName="Show debug info">
// <SampleValue>false</SampleValue>
// </Property>
// </Fields>
// </Properties>
// <InputConstraints>
// <Entity type="netcap.PCAP" min="1" max="1"/>
// </InputConstraints>
// <OutputEntities/>
// <defaultSets/>
// <StealthLevel>0</StealthLevel>

type Transform struct {
	Transform        XMLTransform           `xml:"MaltegoTransform"`
	TransformAdapter string                 `xml:"TransformAdapter"`
	Properties       XMLTransformProperties `xml:"Properties"`
	Constraints      InputConstraints       `xml:"InputConstraints"`
	OutputEntities   string                 `xml:"OutputEntities"`
	DefaultSets      string                 `xml:"defaultSets"`
	StealthLevel     string                 `xml:"StealthLevel"`
}

// <MaltegoTransform name="netcap.ToAuditRecords" displayName="To Audit Records [NETCAP]" abstract="false" template="false" visibility="public" description="Transform PCAP file into audit records" author="Philipp Mieden" requireDisplayInfo="false">
type XMLTransform struct {
	Name               string `xml:"name,attr"`
	DisplayName        string `xml:"displayName,attr"`
	Abstract           bool   `xml:"abstract,attr"`
	Template           bool   `xml:"template,attr"`
	Visibility         string `xml:"visibility,attr"`
	Description        string `xml:"description,attr"`
	Author             string `xml:"author,attr"`
	RequireDisplayInfo bool   `xml:"requireDisplayInfo,attr"`
}

type XMLTransformProperties struct {
	XMLName xml.Name `xml:"Properties"`
	Text    string   `xml:",chardata"`
	Fields  struct {
		Text     string `xml:",chardata"`
		Property []struct {
			Text         string `xml:",chardata"`
			Name         string `xml:"name,attr"`
			Type         string `xml:"type,attr"`
			Nullable     string `xml:"nullable,attr"`
			Hidden       string `xml:"hidden,attr"`
			Readonly     string `xml:"readonly,attr"`
			Description  string `xml:"description,attr"`
			Popup        string `xml:"popup,attr"`
			Abstract     string `xml:"abstract,attr"`
			Visibility   string `xml:"visibility,attr"`
			Auth         string `xml:"auth,attr"`
			DisplayName  string `xml:"displayName,attr"`
			SampleValue  string `xml:"SampleValue"`
			DefaultValue string `xml:"DefaultValue"`
		} `xml:"Property"`
	} `xml:"Fields"`
}

type InputConstraints struct {
	XMLName xml.Name `xml:"InputConstraints"`
	Text    string   `xml:",chardata"`
	Entity  struct {
		Text string `xml:",chardata"`
		Type string `xml:"type,attr"`
		Min  string `xml:"min,attr"`
		Max  string `xml:"max,attr"`
	} `xml:"Entity"`
}

// Settings

// File: TransformRepositories/Local/netcap.ToAuditRecords.transformsettings

// </MaltegoTransform>
// <TransformSettings enabled="true" disclaimerAccepted="false" showHelp="true" runWithAll="true" favorite="false">
//    <Properties>
//       <Property name="transform.local.command" type="string" popup="false">/usr/local/bin/net</Property>
//       <Property name="transform.local.parameters" type="string" popup="false">transform ToAuditRecords</Property>
//       <Property name="transform.local.working-directory" type="string" popup="false">/usr/local/</Property>
//       <Property name="transform.local.debug" type="boolean" popup="false">true</Property>
//    </Properties>
// </TransformSettings>

type TransformSettings struct {
	XMLName  xml.Name `xml:"Properties"`
	Text     string   `xml:",chardata"`
	Property []struct {
		Text  string `xml:",chardata"`
		Name  string `xml:"name,attr"`
		Type  string `xml:"type,attr"`
		Popup string `xml:"popup,attr"`
	} `xml:"Property"`
}
