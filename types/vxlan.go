package types

import "strconv"

func (a VXLAN) CSVHeader() []string {
	return filter([]string{
		"Timestamp",
		"ValidIDFlag",      //  bool
		"VNI",              //  uint32
		"GBPExtension",     //  bool
		"GBPDontLearn",     //  bool
		"GBPApplied",       //  bool
		"GBPGroupPolicyID", //  int32
	})
}

func (a VXLAN) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(a.Timestamp),
		strconv.FormatBool(a.ValidIDFlag),  //  bool
		formatUint32(a.VNI),                //  uint32
		strconv.FormatBool(a.GBPExtension), //  bool
		strconv.FormatBool(a.GBPDontLearn), //  bool
		strconv.FormatBool(a.GBPApplied),   //  bool
		formatInt32(a.GBPGroupPolicyID),    //  int32
	})
}

func (a VXLAN) NetcapTimestamp() string {
	return a.Timestamp
}
