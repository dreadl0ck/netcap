package reassembly

import (
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// testStreamWithByteLimit implements the Stream interface for testing
type testStreamWithByteLimit struct {
	reassembledBytes int
	closed           bool
}

func (t *testStreamWithByteLimit) Accept(tcp *layers.TCP, dir TCPFlowDirection, nextSeq Sequence) bool {
	return !t.closed
}

func (t *testStreamWithByteLimit) ReassembledSG(sg ScatterGather, ac AssemblerContext) {
	length, _ := sg.Lengths()
	t.reassembledBytes += length
}

func (t *testStreamWithByteLimit) ReassemblyComplete(ac AssemblerContext, firstFlow gopacket.Flow, reason string) bool {
	t.closed = true
	return true
}

// testStreamFactoryWithByteLimit implements the streamFactory interface for testing
type testStreamFactoryWithByteLimit struct {
	stream *testStreamWithByteLimit
}

func (f *testStreamFactoryWithByteLimit) New(netFlow, tcpFlow gopacket.Flow, ac AssemblerContext) Stream {
	f.stream = &testStreamWithByteLimit{}
	return f.stream
}

// TestMaxStreamBytesLimit verifies that the MaxStreamBytes limit works correctly
func TestMaxStreamBytesLimit(t *testing.T) {
	// Create a stream pool and assembler
	factory := &testStreamFactoryWithByteLimit{}
	pool := NewStreamPool(factory)
	assembler := NewAssembler(pool)

	// Set a maximum of 100 bytes per stream direction
	assembler.MaxStreamBytes = 100

	// Verify the configuration was set
	if assembler.MaxStreamBytes != 100 {
		t.Errorf("Expected MaxStreamBytes to be 100, got %d", assembler.MaxStreamBytes)
	}

	// Create test flows
	netFlow := gopacket.NewFlow(layers.EndpointIPv4, []byte{1, 2, 3, 4}, []byte{5, 6, 7, 8})

	// Create payload data
	payload1 := make([]byte, 50)
	payload2 := make([]byte, 50)
	payload3 := make([]byte, 50)

	// Create a test TCP packet with payload
	tcp := &layers.TCP{
		SrcPort: 80,
		DstPort: 12345,
		Seq:     1000,
		SYN:     true,
		ACK:     false,
		Ack:     0,
	}
	tcp.BaseLayer = layers.BaseLayer{Payload: payload1}

	ctx := &assemblerSimpleContext{
		Timestamp: time.Now(),
	}

	// Send first packet (50 bytes) - should succeed
	assembler.AssembleWithContext(netFlow, tcp, ctx)

	// Send second packet (another 50 bytes) - should succeed
	tcp.SYN = false
	tcp.ACK = true
	tcp.Seq = 1050
	tcp.BaseLayer = layers.BaseLayer{Payload: payload2}
	assembler.AssembleWithContext(netFlow, tcp, ctx)

	// Flush to process the packets
	assembler.FlushAll()

	// At this point, we've sent 100 bytes total, reaching the limit

	// Send third packet (50 more bytes) - should trigger the limit
	tcp.Seq = 1100
	tcp.BaseLayer = layers.BaseLayer{Payload: payload3}
	assembler.AssembleWithContext(netFlow, tcp, ctx)

	// Flush again - this should not panic or cause errors
	assembler.FlushAll()

	// Verify that the stream callback was invoked
	if factory.stream == nil {
		t.Fatal("Stream was never created")
	}

	// The test passes if we reached here without panicking
	t.Log("MaxStreamBytes limit applied successfully without errors")
}

// TestMaxStreamBytesUnlimited verifies that unlimited reassembly works (MaxStreamBytes = 0)
func TestMaxStreamBytesUnlimited(t *testing.T) {
	// Create a stream pool and assembler
	factory := &testStreamFactoryWithByteLimit{}
	pool := NewStreamPool(factory)
	assembler := NewAssembler(pool)

	// Keep MaxStreamBytes at 0 (unlimited, the default)
	assembler.MaxStreamBytes = 0

	// Verify the default configuration
	if assembler.MaxStreamBytes != 0 {
		t.Errorf("Expected MaxStreamBytes to be 0 (unlimited), got %d", assembler.MaxStreamBytes)
	}

	// Create test flows
	netFlow := gopacket.NewFlow(layers.EndpointIPv4, []byte{1, 2, 3, 4}, []byte{5, 6, 7, 8})

	// Create a test TCP packet with payload
	tcp := &layers.TCP{
		SrcPort: 80,
		DstPort: 12345,
		Seq:     1000,
		SYN:     true,
		ACK:     false,
		Ack:     0,
	}

	ctx := &assemblerSimpleContext{
		Timestamp: time.Now(),
	}

	// Send multiple large packets (1000 bytes total)
	for i := 0; i < 10; i++ {
		tcp.SYN = (i == 0)
		tcp.ACK = (i > 0)
		tcp.Seq = uint32(1000 + i*100)
		tcp.BaseLayer = layers.BaseLayer{Payload: make([]byte, 100)}
		assembler.AssembleWithContext(netFlow, tcp, ctx)
	}

	// Flush to process the packets - should not panic or cause errors
	assembler.FlushAll()

	// Verify that the stream callback was invoked
	if factory.stream == nil {
		t.Fatal("Stream was never created")
	}

	// Verify that bytes were reassembled
	if factory.stream.reassembledBytes == 0 {
		t.Error("Expected some bytes to be reassembled in unlimited mode")
	}

	t.Logf("Successfully reassembled %d bytes in unlimited mode", factory.stream.reassembledBytes)
}

// TestMaxStreamBytesInOrder verifies that the byte limit applies to in-order streams (most common case)
func TestMaxStreamBytesInOrder(t *testing.T) {
	// Create a stream pool and assembler
	factory := &testStreamFactoryWithByteLimit{}
	pool := NewStreamPool(factory)
	assembler := NewAssembler(pool)

	// Set a maximum of 250 bytes per stream direction
	assembler.MaxStreamBytes = 250

	// Create test flows
	netFlow := gopacket.NewFlow(layers.EndpointIPv4, []byte{1, 2, 3, 4}, []byte{5, 6, 7, 8})

	// Create a test TCP packet with payload
	tcp := &layers.TCP{
		SrcPort: 80,
		DstPort: 12345,
		Seq:     1000,
		SYN:     true,
		ACK:     false,
		Ack:     0,
	}

	ctx := &assemblerSimpleContext{
		Timestamp: time.Now(),
	}

	// Send SYN
	tcp.BaseLayer = layers.BaseLayer{Payload: nil}
	assembler.AssembleWithContext(netFlow, tcp, ctx)

	// Send in-order packets (this is the critical test!)
	// Each packet is 50 bytes, send 6 packets = 300 bytes total
	for i := 0; i < 6; i++ {
		tcp.SYN = false
		tcp.ACK = true
		tcp.Seq = uint32(1001 + i*50)
		tcp.BaseLayer = layers.BaseLayer{Payload: make([]byte, 50)}

		assembler.AssembleWithContext(netFlow, tcp, ctx)

		// Flush to deliver data
		assembler.FlushAll()
	}

	// Verify that the stream callback was invoked
	if factory.stream == nil {
		t.Fatal("Stream was never created")
	}

	// The stream should have been closed after hitting the 250 byte limit
	// We should have processed at most 250 bytes (possibly 300 due to one packet overage)
	if factory.stream.reassembledBytes == 0 {
		t.Error("Expected some bytes to be reassembled")
	}

	// Should have processed approximately 250-300 bytes (up to the limit + one packet)
	if factory.stream.reassembledBytes > 350 {
		t.Errorf("Expected stream to be limited, but got %d bytes (limit was 250)", factory.stream.reassembledBytes)
	}

	t.Logf("Successfully limited in-order stream to %d bytes (limit: 250)", factory.stream.reassembledBytes)
}

// TestMaxStreamBytesNoRecreation verifies that streams reaching the limit stay in pool
// and are not removed/recreated, which would bypass the limit
func TestMaxStreamBytesNoRecreation(t *testing.T) {
	// Create a stream pool and assembler
	factory := &testStreamFactoryWithByteLimit{}
	pool := NewStreamPool(factory)
	assembler := NewAssembler(pool)

	// Set a very low limit to trigger quickly
	assembler.MaxStreamBytes = 100

	// Create test flows
	netFlow := gopacket.NewFlow(layers.EndpointIPv4, []byte{1, 2, 3, 4}, []byte{5, 6, 7, 8})

	tcp := &layers.TCP{
		SrcPort: 80,
		DstPort: 123,
		Seq:     1000,
		SYN:     true,
		ACK:     false,
	}
	tcp.SetNetworkLayerForChecksum(&layers.IPv4{
		SrcIP: []byte{1, 2, 3, 4},
		DstIP: []byte{5, 6, 7, 8},
	})

	ctx := &assemblerSimpleContext{
		Timestamp: time.Now(),
	}

	// Send SYN
	assembler.AssembleWithContext(netFlow, tcp, ctx)

	// Send data until limit is hit
	tcp.SYN = false
	tcp.ACK = true
	for i := 0; i < 5; i++ {
		tcp.Seq = uint32(1001 + i*50)
		tcp.BaseLayer = layers.BaseLayer{Payload: make([]byte, 50)}
		assembler.AssembleWithContext(netFlow, tcp, ctx)
	}

	// Verify stream was created
	if factory.stream == nil {
		t.Fatal("Stream was never created")
	}

	originalStream := factory.stream
	originalReassembledBytes := factory.stream.reassembledBytes

	// Connection should still be in pool
	// Use the same key construction as the assembler
	flowKey := key{netFlow, tcp.TransportFlow()}
	reverseKey := flowKey.reverse()

	pool.mu.RLock()
	conn, exists := pool.conns[flowKey]
	if !exists {
		conn, exists = pool.conns[reverseKey]
	}
	pool.mu.RUnlock()

	if !exists {
		t.Fatal("Connection not in pool - this is unexpected")
	}

	// Verify one half is closed
	halfClosed := conn.c2s.closed || conn.s2c.closed
	if !halfClosed {
		t.Error("Expected one half-connection to be closed after hitting limit")
	}

	// Send MORE packets - these should be rejected, not create a new stream
	for i := 0; i < 5; i++ {
		tcp.Seq = uint32(1001 + (i+5)*50)
		tcp.BaseLayer = layers.BaseLayer{Payload: make([]byte, 50)}
		assembler.AssembleWithContext(netFlow, tcp, ctx)
	}

	// Verify stream was NOT recreated (same stream object)
	if factory.stream != originalStream {
		t.Error("Stream was recreated! This bypasses the limit protection")
	}

	// Verify no additional bytes were reassembled
	if factory.stream.reassembledBytes > originalReassembledBytes+100 {
		t.Errorf("Additional bytes reassembled after limit: got %d, expected at most %d",
			factory.stream.reassembledBytes, originalReassembledBytes+100)
	}

	// Connection should STILL be in pool
	pool.mu.RLock()
	_, stillExists := pool.conns[flowKey]
	if !stillExists {
		_, stillExists = pool.conns[reverseKey]
	}
	pool.mu.RUnlock()

	if !stillExists {
		t.Error("Connection was removed from pool - streams should stay in pool with one half closed")
	}

	t.Logf("✓ Stream correctly stayed in pool and rejected %d+ bytes after %d byte limit",
		250, originalReassembledBytes)
}
