//go:build linux

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
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	nfqueue "github.com/florianl/go-nfqueue/v2"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// NFQueueHandler handles packets from netfilter queue.
type NFQueueHandler struct {
	queue    *nfqueue.Nfqueue
	queueNum uint16
	engine   *Engine
	injector *RawInjector
	config   *EngineConfig

	// Mutex for thread-safe operations
	mu sync.Mutex

	// Context for cancellation
	ctx    context.Context
	cancel context.CancelFunc

	// Statistics
	packetsReceived uint64
	packetsAccepted uint64
	packetsDropped  uint64
	packetsModified uint64

	// iptables rules that were added
	iptablesRules []string
}

// RawInjector handles raw packet injection via raw sockets.
type RawInjector struct {
	iface   string
	sockFd  int
	ifIndex int
	mu      sync.Mutex
}

// NewNFQueueHandler creates a new nfqueue handler.
func NewNFQueueHandler(engine *Engine, config *EngineConfig) (*NFQueueHandler, error) {
	ctx, cancel := context.WithCancel(context.Background())

	handler := &NFQueueHandler{
		queueNum: config.QueueNum,
		engine:   engine,
		config:   config,
		ctx:      ctx,
		cancel:   cancel,
	}

	// Create raw injector if interface is specified
	if config.Interface != "" {
		injector, err := NewRawInjector(config.Interface)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to create raw injector: %w", err)
		}
		handler.injector = injector
	}

	return handler, nil
}

// Start begins processing packets from the nfqueue.
func (h *NFQueueHandler) Start() error {
	// Configure nfqueue
	nfqConfig := nfqueue.Config{
		NfQueue:      h.queueNum,
		MaxPacketLen: 65535,
		MaxQueueLen:  h.config.MaxQueueLen,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 100 * time.Millisecond,
	}

	// Open nfqueue
	nf, err := nfqueue.Open(&nfqConfig)
	if err != nil {
		return fmt.Errorf("failed to open nfqueue: %w", err)
	}
	h.queue = nf

	// Set up iptables rules if configured
	if h.config.AutoIPTables {
		if err := h.setupIPTables(); err != nil {
			h.queue.Close()
			return fmt.Errorf("failed to setup iptables: %w", err)
		}
	}

	// Register packet handler
	err = h.queue.RegisterWithErrorFunc(h.ctx, h.handlePacket, h.handleError)
	if err != nil {
		h.cleanupIPTables()
		h.queue.Close()
		return fmt.Errorf("failed to register packet handler: %w", err)
	}

	return nil
}

// handlePacket processes a packet from nfqueue.
func (h *NFQueueHandler) handlePacket(attr nfqueue.Attribute) int {
	h.mu.Lock()
	h.packetsReceived++
	h.mu.Unlock()

	// Get packet data
	if attr.Payload == nil || len(*attr.Payload) == 0 {
		h.setVerdict(attr, nfqueue.NfAccept, nil)
		return 0
	}

	payload := *attr.Payload

	// Determine base layer based on packet structure
	// nfqueue typically provides IP packets (no ethernet header)
	var baseLayer gopacket.LayerType
	if len(payload) > 0 {
		version := payload[0] >> 4
		if version == 4 {
			baseLayer = layers.LayerTypeIPv4
		} else if version == 6 {
			baseLayer = layers.LayerTypeIPv6
		} else {
			// Unknown, try ethernet
			baseLayer = layers.LayerTypeEthernet
		}
	}

	// Decode packet
	pkt := gopacket.NewPacket(payload, baseLayer, gopacket.Default)

	// Process packet through injection engine
	results, err := h.engine.ProcessPacket(pkt, h.config.Interface)
	if err != nil {
		if h.config.Verbose {
			fmt.Printf("Error processing packet: %v\n", err)
		}
		h.setVerdict(attr, nfqueue.NfAccept, nil)
		return 0
	}

	// Determine verdict and handle actions
	verdict := nfqueue.NfAccept
	var modifiedPayload []byte

	for _, result := range results {
		// In dry-run mode, log actions but don't actually modify/inject/drop
		if h.config.DryRun {
			if h.config.Verbose {
				fmt.Printf("[DRY-RUN] Rule %s: action=%s, drop=%v, inject=%d packets\n",
					result.RuleName, result.Action, result.Drop, len(result.InjectPackets))
			}
			continue
		}

		if result.Drop {
			verdict = nfqueue.NfDrop
			h.mu.Lock()
			h.packetsDropped++
			h.mu.Unlock()
		}

		if result.ModifiedPacket != nil {
			modifiedPayload = result.ModifiedPacket
			h.mu.Lock()
			h.packetsModified++
			h.mu.Unlock()
		}

		// Inject additional packets
		if len(result.InjectPackets) > 0 && h.injector != nil {
			for _, pktData := range result.InjectPackets {
				if err := h.injector.InjectPacket(pktData); err != nil {
					if h.config.Verbose {
						fmt.Printf("Failed to inject packet: %v\n", err)
					}
				}
			}
		}

		// Handle delay (note: this blocks the handler - consider async handling for production)
		if result.Delay > 0 {
			time.Sleep(result.Delay)
		}
	}

	// Set verdict
	h.setVerdict(attr, verdict, modifiedPayload)

	if verdict == nfqueue.NfAccept {
		h.mu.Lock()
		h.packetsAccepted++
		h.mu.Unlock()
	}

	return 0
}

// setVerdict sets the verdict for a packet.
func (h *NFQueueHandler) setVerdict(attr nfqueue.Attribute, verdict int, modifiedPayload []byte) {
	if attr.PacketID == nil {
		return
	}

	if modifiedPayload != nil {
		h.queue.SetVerdictModPacket(*attr.PacketID, verdict, modifiedPayload)
	} else {
		h.queue.SetVerdict(*attr.PacketID, verdict)
	}
}

// handleError handles nfqueue errors.
func (h *NFQueueHandler) handleError(err error) int {
	if h.config.Verbose {
		fmt.Printf("NFQueue error: %v\n", err)
	}
	return 0
}

// setupIPTables configures iptables rules to redirect traffic to nfqueue.
func (h *NFQueueHandler) setupIPTables() error {
	// Build iptables rules
	var rules []string

	// Base rule components
	baseRule := fmt.Sprintf("-j NFQUEUE --queue-num %d", h.queueNum)

	// Add target filter if specified
	if h.config.IPTablesTarget != "" {
		baseRule = h.config.IPTablesTarget + " " + baseRule
	}

	// Create rules for INPUT, OUTPUT, and FORWARD chains
	chains := []string{"INPUT", "OUTPUT", "FORWARD"}
	for _, chain := range chains {
		rule := fmt.Sprintf("-A %s %s", chain, baseRule)
		rules = append(rules, rule)
	}

	// Apply rules
	for _, rule := range rules {
		args := strings.Fields(rule)
		cmd := exec.Command("iptables", args...)
		if output, err := cmd.CombinedOutput(); err != nil {
			// Clean up any rules we've added
			h.cleanupIPTables()
			return fmt.Errorf("failed to add iptables rule '%s': %v (%s)", rule, err, string(output))
		}
		h.iptablesRules = append(h.iptablesRules, rule)
	}

	return nil
}

// cleanupIPTables removes iptables rules that were added.
func (h *NFQueueHandler) cleanupIPTables() {
	for _, rule := range h.iptablesRules {
		// Convert -A to -D for deletion
		deleteRule := strings.Replace(rule, "-A ", "-D ", 1)
		args := strings.Fields(deleteRule)
		cmd := exec.Command("iptables", args...)
		cmd.Run() // Ignore errors during cleanup
	}
	h.iptablesRules = nil
}

// Stop shuts down the nfqueue handler.
func (h *NFQueueHandler) Stop() error {
	h.cancel()

	// Clean up iptables rules
	h.cleanupIPTables()

	// Close nfqueue
	if h.queue != nil {
		if err := h.queue.Close(); err != nil {
			return err
		}
	}

	// Close raw injector
	if h.injector != nil {
		if err := h.injector.Close(); err != nil {
			return err
		}
	}

	return nil
}

// GetStats returns nfqueue handler statistics.
func (h *NFQueueHandler) GetStats() (received, accepted, dropped, modified uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.packetsReceived, h.packetsAccepted, h.packetsDropped, h.packetsModified
}

// NewRawInjector creates a new raw packet injector for an interface.
func NewRawInjector(iface string) (*RawInjector, error) {
	// Get interface index
	netIface, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface %s not found: %w", iface, err)
	}

	// Create raw socket for packet injection
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("failed to create raw socket: %w", err)
	}

	// Bind to interface
	addr := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  netIface.Index,
	}

	if err := syscall.Bind(fd, &addr); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to bind to interface: %w", err)
	}

	return &RawInjector{
		iface:   iface,
		sockFd:  fd,
		ifIndex: netIface.Index,
	}, nil
}

// InjectPacket sends a raw packet on the wire.
func (ri *RawInjector) InjectPacket(data []byte) error {
	ri.mu.Lock()
	defer ri.mu.Unlock()

	addr := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  ri.ifIndex,
	}

	return syscall.Sendto(ri.sockFd, data, 0, &addr)
}

// Close closes the raw socket.
func (ri *RawInjector) Close() error {
	ri.mu.Lock()
	defer ri.mu.Unlock()
	return syscall.Close(ri.sockFd)
}

// htons converts a uint16 from host to network byte order.
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

// IsNFQueueSupported returns true on Linux.
func IsNFQueueSupported() bool {
	return true
}

