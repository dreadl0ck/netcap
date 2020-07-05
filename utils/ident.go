package utils

import "strings"

// e.g: 192.168.1.47->165.227.109.154-53032->80
// to 53032->80
func ChopTransportIdent(in string) string {
	arr := strings.Split(in, "-")
	if len(arr) != 4 {
		return ""
	}
	return arr[2] + "-" + arr[3]
}

// e.g: 192.168.1.47->165.227.109.154-53032->80
// to 165.227.109.154->192.168.1.47-80->53032
func ReverseIdent(i string) string {
	arr := strings.Split(i, "->")
	if len(arr) != 3 {
		return ""
	}
	middle := strings.Split(arr[1], "-")
	if len(middle) != 2 {
		return ""
	}
	return middle[0] + "->" + arr[0] + "-" + arr[2] + "->" + middle[1]
}

// e.g: 192.168.1.47->165.227.109.154-53032->80
// to 192.168.1.47, 53032, 165.227.109.154, 80
func ParseIdent(i string) (srcIP, srcPort, dstIP, dstPort string) {
	arr := strings.Split(i, "->")
	if len(arr) != 3 {
		return
	}
	middle := strings.Split(arr[1], "-")
	if len(middle) != 2 {
		return
	}
	return arr[0], middle[1], middle[0], arr[2]
}
