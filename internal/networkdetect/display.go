package networkdetect

func DisplayName(id string) string {
	switch id {
	case "c2.beacon":
		return "Periodic Network Beacon"
	case "network.scan":
		return "Network Reconnaissance Pattern"
	case "smtp.fanout":
		return "Outbound SMTP Fan-Out"
	case "udp.fanout":
		return "Outbound UDP Fan-Out"
	case "dns.dga":
		return "DNS Name-Generation Pattern"
	case "dns.tunnel":
		return "Possible DNS Tunnel"
	case "policy.cleartext-service":
		return "Traffic on a Cleartext Service Port"
	default:
		return id
	}
}
