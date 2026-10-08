package collector

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/dreadl0ck/netcap/internal/flowexport"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"go.uber.org/zap"
)

func (c *Collector) initFlowExports() error {
	if !c.config.FlowExports {
		return nil
	}
	c.flowExportPorts = map[layers.UDPPort]bool{}
	ports := c.config.FlowExportPorts
	if ports == "" {
		ports = "2055,4739,6343,9995,9996"
	}
	for _, raw := range strings.Split(ports, ",") {
		n, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 16)
		if err != nil || n == 0 {
			return fmt.Errorf("invalid flow-export UDP port %q", raw)
		}
		c.flowExportPorts[layers.UDPPort(n)] = true
	}
	directory := c.config.DecoderConfig.Out
	if directory == "" {
		directory = "."
	}
	r, err := flowexport.NewRecorder(directory, flowexport.DefaultConfig())
	if err != nil {
		return err
	}
	c.flowExports = r
	return nil
}

// Called under dispatchMu before packet ownership transfers to a worker.
func (c *Collector) observeFlowExport(packet gopacket.Packet) {
	if c.flowExports == nil {
		return
	}
	udp, ok := packet.TransportLayer().(*layers.UDP)
	if !ok || !c.flowExportPorts[udp.DstPort] || packet.NetworkLayer() == nil {
		return
	}
	network := packet.NetworkLayer().NetworkFlow()
	envelope := flowexport.Envelope{Exporter: net.JoinHostPort(network.Src().String(), strconv.Itoa(int(udp.SrcPort))), Collector: net.JoinHostPort(network.Dst().String(), strconv.Itoa(int(udp.DstPort))), ReceivedNs: packet.Metadata().CaptureInfo.Timestamp.UnixNano(), PacketOrdinal: c.flowIngressOrdinal - 1}
	if err := c.flowExports.Observe(udp.Payload, envelope); err != nil {
		c.flowExportError = err
		c.log.Error("flow-export storage failure", zap.Error(err))
	}
}
