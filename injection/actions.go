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

package injection

import (
	"bytes"
	"fmt"
	"net"
	"regexp"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// ActionHandler is an interface for implementing injection actions.
type ActionHandler interface {
	Execute(ctx *InjectionContext, config map[string]interface{}) (*ActionResult, error)
}

// ModifyPayloadHandler handles payload modification actions.
type ModifyPayloadHandler struct{}

// Execute performs payload modification using search/replace or regex.
// Supports the following action_config options:
//   - search: string to search for (literal or regex pattern)
//   - replace: replacement string (supports regex capture groups like $1, $2 when regex=true)
//   - regex: bool (optional, default false) - if true, search is treated as a regex pattern
func (h *ModifyPayloadHandler) Execute(ctx *InjectionContext, config map[string]interface{}) (*ActionResult, error) {
	result := &ActionResult{
		Action:    ActionModifyPayload,
		Timestamp: time.Now(),
		Details:   make(map[string]interface{}),
	}

	// Get search and replace patterns from config
	searchStr, ok := config["search"].(string)
	if !ok {
		return nil, fmt.Errorf("modify_payload: missing 'search' in action_config")
	}

	replaceStr, ok := config["replace"].(string)
	if !ok {
		return nil, fmt.Errorf("modify_payload: missing 'replace' in action_config")
	}

	// Check if regex mode is enabled
	useRegex := false
	if regexVal, ok := config["regex"].(bool); ok {
		useRegex = regexVal
	}

	// Perform replacement on payload
	if len(ctx.Payload) == 0 {
		result.Success = false
		result.Error = fmt.Errorf("no payload to modify")
		return result, nil
	}

	var modified []byte
	var err error

	if useRegex {
		// Regex mode
		modified, err = h.regexReplace(ctx.Payload, searchStr, replaceStr)
		if err != nil {
			return nil, fmt.Errorf("modify_payload: regex error: %w", err)
		}
		result.Details["regex"] = true
	} else {
		// Literal string replacement
		search := []byte(searchStr)
		replace := []byte(replaceStr)
		modified = bytes.Replace(ctx.Payload, search, replace, -1)
		result.Details["regex"] = false
	}

	if bytes.Equal(modified, ctx.Payload) {
		result.Success = true
		result.Details["modified"] = false
		return result, nil
	}

	// Rebuild packet with modified payload
	modifiedPacket, err := h.rebuildPacketWithPayload(ctx, modified)
	if err != nil {
		return nil, fmt.Errorf("failed to rebuild packet: %w", err)
	}

	result.Success = true
	result.ModifiedPacket = modifiedPacket
	result.Details["modified"] = true
	result.Details["search"] = searchStr
	result.Details["replace"] = replaceStr
	result.Details["original_len"] = len(ctx.Payload)
	result.Details["new_len"] = len(modified)

	return result, nil
}

// regexReplace performs regex-based replacement on the payload.
func (h *ModifyPayloadHandler) regexReplace(payload []byte, pattern, replace string) ([]byte, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern: %w", err)
	}

	return re.ReplaceAll(payload, []byte(replace)), nil
}

// rebuildPacketWithPayload reconstructs the packet with a new payload.
func (h *ModifyPayloadHandler) rebuildPacketWithPayload(ctx *InjectionContext, newPayload []byte) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	var serializeLayers []gopacket.SerializableLayer

	// Add Ethernet layer
	if ctx.Ethernet != nil {
		serializeLayers = append(serializeLayers, ctx.Ethernet)
	}

	// Add IP layer
	if ctx.IPv4 != nil {
		serializeLayers = append(serializeLayers, ctx.IPv4)
	} else if ctx.IPv6 != nil {
		serializeLayers = append(serializeLayers, ctx.IPv6)
	}

	// Add transport layer
	if ctx.TCP != nil {
		if ctx.IPv4 != nil {
			ctx.TCP.SetNetworkLayerForChecksum(ctx.IPv4)
		} else if ctx.IPv6 != nil {
			ctx.TCP.SetNetworkLayerForChecksum(ctx.IPv6)
		}
		serializeLayers = append(serializeLayers, ctx.TCP)
	} else if ctx.UDP != nil {
		if ctx.IPv4 != nil {
			ctx.UDP.SetNetworkLayerForChecksum(ctx.IPv4)
		} else if ctx.IPv6 != nil {
			ctx.UDP.SetNetworkLayerForChecksum(ctx.IPv6)
		}
		serializeLayers = append(serializeLayers, ctx.UDP)
	}

	// Add payload
	serializeLayers = append(serializeLayers, gopacket.Payload(newPayload))

	err := gopacket.SerializeLayers(buf, opts, serializeLayers...)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// TCPRSTHandler handles TCP RST injection.
type TCPRSTHandler struct{}

// Execute generates and returns a TCP RST packet.
func (h *TCPRSTHandler) Execute(ctx *InjectionContext, config map[string]interface{}) (*ActionResult, error) {
	result := &ActionResult{
		Action:    ActionInjectTCPRST,
		Timestamp: time.Now(),
		Details:   make(map[string]interface{}),
	}

	if ctx.TCP == nil {
		return nil, fmt.Errorf("inject_tcp_rst: packet does not have TCP layer")
	}

	// Build RST packet (swap src/dst)
	rstPacket, err := h.buildTCPRST(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to build TCP RST: %w", err)
	}

	result.Success = true
	result.InjectPackets = append(result.InjectPackets, rstPacket)
	result.Drop = true // Drop original packet after sending RST
	result.Details["src_ip"] = ctx.DstIP()
	result.Details["dst_ip"] = ctx.SrcIP()
	result.Details["src_port"] = ctx.DstPort()
	result.Details["dst_port"] = ctx.SrcPort()

	return result, nil
}

// buildTCPRST creates a TCP RST packet.
func (h *TCPRSTHandler) buildTCPRST(ctx *InjectionContext) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	var serializeLayers []gopacket.SerializableLayer

	// Add Ethernet layer if present (nfqueue often provides IP-only packets)
	if ctx.Ethernet != nil {
		eth := &layers.Ethernet{
			SrcMAC:       ctx.Ethernet.DstMAC,
			DstMAC:       ctx.Ethernet.SrcMAC,
			EthernetType: ctx.Ethernet.EthernetType,
		}
		serializeLayers = append(serializeLayers, eth)
	}

	if ctx.IPv4 != nil {
		ipv4 := &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
			SrcIP:    ctx.IPv4.DstIP,
			DstIP:    ctx.IPv4.SrcIP,
		}

		tcp := &layers.TCP{
			SrcPort: ctx.TCP.DstPort,
			DstPort: ctx.TCP.SrcPort,
			Seq:     ctx.TCP.Ack,
			Ack:     ctx.TCP.Seq + 1,
			RST:     true,
			ACK:     true,
			Window:  0,
		}
		tcp.SetNetworkLayerForChecksum(ipv4)

		serializeLayers = append(serializeLayers, ipv4, tcp)
		return h.serializeLayerSlice(buf, opts, serializeLayers)
	}

	if ctx.IPv6 != nil {
		ipv6 := &layers.IPv6{
			Version:    6,
			HopLimit:   64,
			NextHeader: layers.IPProtocolTCP,
			SrcIP:      ctx.IPv6.DstIP,
			DstIP:      ctx.IPv6.SrcIP,
		}

		tcp := &layers.TCP{
			SrcPort: ctx.TCP.DstPort,
			DstPort: ctx.TCP.SrcPort,
			Seq:     ctx.TCP.Ack,
			Ack:     ctx.TCP.Seq + 1,
			RST:     true,
			ACK:     true,
			Window:  0,
		}
		tcp.SetNetworkLayerForChecksum(ipv6)

		serializeLayers = append(serializeLayers, ipv6, tcp)
		return h.serializeLayerSlice(buf, opts, serializeLayers)
	}

	return nil, fmt.Errorf("no IP layer found")
}

func (h *TCPRSTHandler) serializeLayers(buf gopacket.SerializeBuffer, opts gopacket.SerializeOptions, layers ...gopacket.SerializableLayer) ([]byte, error) {
	err := gopacket.SerializeLayers(buf, opts, layers...)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (h *TCPRSTHandler) serializeLayerSlice(buf gopacket.SerializeBuffer, opts gopacket.SerializeOptions, layers []gopacket.SerializableLayer) ([]byte, error) {
	err := gopacket.SerializeLayers(buf, opts, layers...)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DNSSpoofHandler handles DNS response spoofing.
type DNSSpoofHandler struct{}

// Execute generates a spoofed DNS response.
func (h *DNSSpoofHandler) Execute(ctx *InjectionContext, config map[string]interface{}) (*ActionResult, error) {
	result := &ActionResult{
		Action:    ActionInjectDNS,
		Timestamp: time.Now(),
		Details:   make(map[string]interface{}),
	}

	if ctx.DNS == nil {
		return nil, fmt.Errorf("inject_dns: packet does not have DNS layer")
	}

	// Only spoof queries (QR=0)
	if ctx.DNS.QR {
		result.Success = false
		result.Details["reason"] = "packet is already a response"
		return result, nil
	}

	// Ensure there's at least one question to respond to
	if len(ctx.DNS.Questions) == 0 {
		result.Success = false
		result.Details["reason"] = "DNS query has no questions"
		return result, nil
	}

	// DNS over UDP is required for spoofing (TCP DNS uses different flow)
	if ctx.UDP == nil {
		result.Success = false
		result.Details["reason"] = "DNS over TCP not supported for spoofing"
		return result, nil
	}

	// Get response IP from config
	responseIPStr, ok := config["response_ip"].(string)
	if !ok {
		return nil, fmt.Errorf("inject_dns: missing 'response_ip' in action_config")
	}

	responseIP := net.ParseIP(responseIPStr)
	if responseIP == nil {
		return nil, fmt.Errorf("inject_dns: invalid response_ip: %s", responseIPStr)
	}

	// Get TTL (default 300)
	ttl := uint32(300)
	if ttlVal, ok := config["ttl"].(int); ok {
		ttl = uint32(ttlVal)
	}

	// Build spoofed response
	spoofedPacket, err := h.buildDNSResponse(ctx, responseIP, ttl)
	if err != nil {
		return nil, fmt.Errorf("failed to build DNS response: %w", err)
	}

	result.Success = true
	result.InjectPackets = append(result.InjectPackets, spoofedPacket)
	result.Drop = true // Drop original query to prevent real response
	result.Details["response_ip"] = responseIPStr
	result.Details["ttl"] = ttl
	result.Details["queried_name"] = string(ctx.DNS.Questions[0].Name)

	return result, nil
}

// buildDNSResponse creates a spoofed DNS response.
func (h *DNSSpoofHandler) buildDNSResponse(ctx *InjectionContext, responseIP net.IP, ttl uint32) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	var serializeLayers []gopacket.SerializableLayer

	// Add Ethernet layer if present (nfqueue often provides IP-only packets)
	if ctx.Ethernet != nil {
		eth := &layers.Ethernet{
			SrcMAC:       ctx.Ethernet.DstMAC,
			DstMAC:       ctx.Ethernet.SrcMAC,
			EthernetType: ctx.Ethernet.EthernetType,
		}
		serializeLayers = append(serializeLayers, eth)
	}

	// Determine if response should be A or AAAA based on IP version
	dnsType := layers.DNSTypeA
	if responseIP.To4() == nil {
		dnsType = layers.DNSTypeAAAA
	}

	if ctx.IPv4 != nil {
		ipv4 := &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    ctx.IPv4.DstIP,
			DstIP:    ctx.IPv4.SrcIP,
		}

		udp := &layers.UDP{
			SrcPort: ctx.UDP.DstPort,
			DstPort: ctx.UDP.SrcPort,
		}
		udp.SetNetworkLayerForChecksum(ipv4)

		dnsResponse := h.createDNSResponse(ctx.DNS, responseIP, ttl, dnsType)

		serializeLayers = append(serializeLayers, ipv4, udp, dnsResponse)
	} else if ctx.IPv6 != nil {
		ipv6 := &layers.IPv6{
			Version:    6,
			HopLimit:   64,
			NextHeader: layers.IPProtocolUDP,
			SrcIP:      ctx.IPv6.DstIP,
			DstIP:      ctx.IPv6.SrcIP,
		}

		udp := &layers.UDP{
			SrcPort: ctx.UDP.DstPort,
			DstPort: ctx.UDP.SrcPort,
		}
		udp.SetNetworkLayerForChecksum(ipv6)

		dnsResponse := h.createDNSResponse(ctx.DNS, responseIP, ttl, dnsType)

		serializeLayers = append(serializeLayers, ipv6, udp, dnsResponse)
	} else {
		return nil, fmt.Errorf("no IP layer found")
	}

	err := gopacket.SerializeLayers(buf, opts, serializeLayers...)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (h *DNSSpoofHandler) createDNSResponse(query *layers.DNS, ip net.IP, ttl uint32, dnsType layers.DNSType) *layers.DNS {
	return &layers.DNS{
		ID:           query.ID,
		QR:           true, // Response
		OpCode:       query.OpCode,
		AA:           true, // Authoritative
		RD:           query.RD,
		RA:           true,
		ResponseCode: layers.DNSResponseCodeNoErr,
		Questions:    query.Questions,
		Answers: []layers.DNSResourceRecord{
			{
				Name:  query.Questions[0].Name,
				Type:  dnsType,
				Class: layers.DNSClassIN,
				TTL:   ttl,
				IP:    ip,
			},
		},
	}
}

// ARPSpoofHandler handles ARP reply spoofing.
type ARPSpoofHandler struct{}

// Execute generates a spoofed ARP reply.
func (h *ARPSpoofHandler) Execute(ctx *InjectionContext, config map[string]interface{}) (*ActionResult, error) {
	result := &ActionResult{
		Action:    ActionInjectARP,
		Timestamp: time.Now(),
		Details:   make(map[string]interface{}),
	}

	// Get spoof MAC from config
	spoofMACStr, ok := config["spoof_mac"].(string)
	if !ok {
		return nil, fmt.Errorf("inject_arp: missing 'spoof_mac' in action_config")
	}

	spoofMAC, err := net.ParseMAC(spoofMACStr)
	if err != nil {
		return nil, fmt.Errorf("inject_arp: invalid spoof_mac: %s", spoofMACStr)
	}

	// Get target IP to spoof (optional - defaults to responding to ARP request)
	var targetIP net.IP
	if targetIPStr, ok := config["target_ip"].(string); ok {
		targetIP = net.ParseIP(targetIPStr)
		if targetIP == nil {
			return nil, fmt.Errorf("inject_arp: invalid target_ip: %s", targetIPStr)
		}
	}

	// Build spoofed ARP reply
	spoofedPacket, err := h.buildARPReply(ctx, spoofMAC, targetIP)
	if err != nil {
		return nil, fmt.Errorf("failed to build ARP reply: %w", err)
	}

	result.Success = true
	result.InjectPackets = append(result.InjectPackets, spoofedPacket)
	result.Details["spoof_mac"] = spoofMACStr

	return result, nil
}

// buildARPReply creates a spoofed ARP reply.
func (h *ARPSpoofHandler) buildARPReply(ctx *InjectionContext, spoofMAC net.HardwareAddr, targetIP net.IP) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// If this is an ARP request, respond to it
	var srcIP, dstIP net.IP
	var dstMAC net.HardwareAddr

	if ctx.ARP != nil && ctx.ARP.Operation == layers.ARPRequest {
		// Respond to the ARP request
		srcIP = net.IP(ctx.ARP.DstProtAddress) // IP being requested
		dstIP = net.IP(ctx.ARP.SourceProtAddress)
		dstMAC = net.HardwareAddr(ctx.ARP.SourceHwAddress)
	} else if targetIP != nil {
		// Generate gratuitous ARP
		srcIP = targetIP
		dstIP = targetIP
		dstMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	} else {
		return nil, fmt.Errorf("no ARP context or target_ip specified")
	}

	eth := &layers.Ethernet{
		SrcMAC:       spoofMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeARP,
	}

	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   spoofMAC,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      dstMAC,
		DstProtAddress:    dstIP.To4(),
	}

	err := gopacket.SerializeLayers(buf, opts, eth, arp)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// DelayHandler handles packet delay actions.
type DelayHandler struct{}

// Execute returns a result indicating the packet should be delayed.
func (h *DelayHandler) Execute(ctx *InjectionContext, config map[string]interface{}) (*ActionResult, error) {
	result := &ActionResult{
		Action:    ActionDelay,
		Timestamp: time.Now(),
		Details:   make(map[string]interface{}),
	}

	// Get delay duration from config
	delayMs, ok := config["delay_ms"].(int)
	if !ok {
		return nil, fmt.Errorf("delay: missing 'delay_ms' in action_config")
	}

	result.Success = true
	result.Delay = time.Duration(delayMs) * time.Millisecond
	result.Details["delay_ms"] = delayMs

	return result, nil
}

// HTTPInjectHeaderHandler handles HTTP header injection/modification.
type HTTPInjectHeaderHandler struct{}

// Execute injects or modifies HTTP headers in the payload.
// Supports the following action_config options:
//   - headers: map[string]string of headers to inject/modify
//   - remove_headers: []string of header names to remove
//   - position: "request" or "response" (which headers to modify)
func (h *HTTPInjectHeaderHandler) Execute(ctx *InjectionContext, config map[string]interface{}) (*ActionResult, error) {
	result := &ActionResult{
		Action:    ActionHTTPInjectHeader,
		Timestamp: time.Now(),
		Details:   make(map[string]interface{}),
	}

	if len(ctx.Payload) == 0 {
		result.Success = false
		result.Error = fmt.Errorf("no payload to modify")
		return result, nil
	}

	payload := ctx.Payload
	modified := false

	// Get headers to inject
	if headersRaw, ok := config["headers"].(map[string]interface{}); ok {
		for name, value := range headersRaw {
			if valueStr, ok := value.(string); ok {
				payload, modified = h.injectHeader(payload, name, valueStr)
			}
		}
		result.Details["injected_headers"] = len(headersRaw)
	}

	// Get headers to remove
	if removeHeaders, ok := config["remove_headers"].([]interface{}); ok {
		for _, headerRaw := range removeHeaders {
			if headerName, ok := headerRaw.(string); ok {
				var wasModified bool
				payload, wasModified = h.removeHeader(payload, headerName)
				if wasModified {
					modified = true
				}
			}
		}
		result.Details["removed_headers"] = len(removeHeaders)
	}

	if !modified {
		result.Success = true
		result.Details["modified"] = false
		return result, nil
	}

	// Rebuild packet with modified payload
	handler := &ModifyPayloadHandler{}
	modifiedPacket, err := handler.rebuildPacketWithPayload(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to rebuild packet: %w", err)
	}

	result.Success = true
	result.ModifiedPacket = modifiedPacket
	result.Details["modified"] = true

	return result, nil
}

// injectHeader adds or replaces an HTTP header in the payload.
func (h *HTTPInjectHeaderHandler) injectHeader(payload []byte, name, value string) ([]byte, bool) {
	headerLine := []byte(name + ": " + value + "\r\n")

	// Find the end of headers (double CRLF)
	headerEnd := bytes.Index(payload, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		return payload, false
	}

	// Check if header already exists (case-insensitive)
	headerPattern := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(name) + `:[^\r\n]*\r\n`)
	if headerPattern.Match(payload[:headerEnd]) {
		// Replace existing header
		modified := headerPattern.ReplaceAll(payload, headerLine)
		return modified, true
	}

	// Insert new header before the end of headers
	result := make([]byte, 0, len(payload)+len(headerLine))
	result = append(result, payload[:headerEnd]...)
	result = append(result, []byte("\r\n")...)
	result = append(result, headerLine...)
	result = append(result, payload[headerEnd+2:]...) // Skip the first \r\n

	return result, true
}

// removeHeader removes an HTTP header from the payload.
func (h *HTTPInjectHeaderHandler) removeHeader(payload []byte, name string) ([]byte, bool) {
	headerPattern := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(name) + `:[^\r\n]*\r\n`)
	if !headerPattern.Match(payload) {
		return payload, false
	}
	return headerPattern.ReplaceAll(payload, nil), true
}

// HTTPSSLStripHandler handles SSL stripping by downgrading HTTPS to HTTP.
type HTTPSSLStripHandler struct{}

// Execute replaces HTTPS URLs with HTTP in the payload.
// This is commonly used in SSL stripping attacks.
func (h *HTTPSSLStripHandler) Execute(ctx *InjectionContext, config map[string]interface{}) (*ActionResult, error) {
	result := &ActionResult{
		Action:    ActionHTTPSSLStrip,
		Timestamp: time.Now(),
		Details:   make(map[string]interface{}),
	}

	if len(ctx.Payload) == 0 {
		result.Success = false
		result.Error = fmt.Errorf("no payload to modify")
		return result, nil
	}

	// Replace https:// with http://
	httpsPattern := regexp.MustCompile(`https://`)
	modified := httpsPattern.ReplaceAll(ctx.Payload, []byte("http://"))

	// Also handle secure cookies (remove Secure flag)
	securePattern := regexp.MustCompile(`(?i);?\s*Secure\s*;?`)
	modified = securePattern.ReplaceAll(modified, []byte(";"))

	// Remove HSTS header if present
	hstsPattern := regexp.MustCompile(`(?i)Strict-Transport-Security:[^\r\n]*\r\n`)
	modified = hstsPattern.ReplaceAll(modified, nil)

	if bytes.Equal(modified, ctx.Payload) {
		result.Success = true
		result.Details["modified"] = false
		return result, nil
	}

	// Rebuild packet with modified payload
	handler := &ModifyPayloadHandler{}
	modifiedPacket, err := handler.rebuildPacketWithPayload(ctx, modified)
	if err != nil {
		return nil, fmt.Errorf("failed to rebuild packet: %w", err)
	}

	result.Success = true
	result.ModifiedPacket = modifiedPacket
	result.Details["modified"] = true
	result.Details["ssl_stripped"] = true

	return result, nil
}

// HTTPRedirectHandler handles HTTP redirect injection.
type HTTPRedirectHandler struct{}

// Execute creates an HTTP redirect response.
// Supports the following action_config options:
//   - location: URL to redirect to (required)
//   - status_code: HTTP status code (default: 302)
func (h *HTTPRedirectHandler) Execute(ctx *InjectionContext, config map[string]interface{}) (*ActionResult, error) {
	result := &ActionResult{
		Action:    ActionHTTPRedirect,
		Timestamp: time.Now(),
		Details:   make(map[string]interface{}),
	}

	// Get redirect location
	location, ok := config["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("http_redirect: missing 'location' in action_config")
	}

	// Get status code (default 302)
	statusCode := 302
	if code, ok := config["status_code"].(int); ok {
		statusCode = code
	}

	// Build redirect response
	statusText := "Found"
	switch statusCode {
	case 301:
		statusText = "Moved Permanently"
	case 302:
		statusText = "Found"
	case 303:
		statusText = "See Other"
	case 307:
		statusText = "Temporary Redirect"
	case 308:
		statusText = "Permanent Redirect"
	}

	body := fmt.Sprintf("<html><body>Redirecting to <a href=\"%s\">%s</a></body></html>", location, location)
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\n"+
		"Location: %s\r\n"+
		"Content-Type: text/html\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: close\r\n"+
		"\r\n%s",
		statusCode, statusText, location, len(body), body)

	// Rebuild packet with redirect response
	handler := &ModifyPayloadHandler{}
	modifiedPacket, err := handler.rebuildPacketWithPayload(ctx, []byte(response))
	if err != nil {
		return nil, fmt.Errorf("failed to rebuild packet: %w", err)
	}

	result.Success = true
	result.ModifiedPacket = modifiedPacket
	result.Drop = false // Forward the redirect response
	result.Details["location"] = location
	result.Details["status_code"] = statusCode

	return result, nil
}

// GetActionHandler returns the appropriate handler for an action type.
func GetActionHandler(action Action) (ActionHandler, error) {
	switch action {
	case ActionModifyPayload:
		return &ModifyPayloadHandler{}, nil
	case ActionInjectTCPRST:
		return &TCPRSTHandler{}, nil
	case ActionInjectDNS:
		return &DNSSpoofHandler{}, nil
	case ActionInjectARP:
		return &ARPSpoofHandler{}, nil
	case ActionDelay:
		return &DelayHandler{}, nil
	case ActionHTTPInjectHeader:
		return &HTTPInjectHeaderHandler{}, nil
	case ActionHTTPSSLStrip:
		return &HTTPSSLStripHandler{}, nil
	case ActionHTTPRedirect:
		return &HTTPRedirectHandler{}, nil
	case ActionAccept, ActionDrop:
		// These don't need handlers - they're just verdicts
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown action type: %s", action)
	}
}
