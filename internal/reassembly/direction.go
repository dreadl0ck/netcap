package reassembly

// TCPFlowDirection distinguish the two half-connections directions.
//
// TCPDirClientToServer is assigned to half-connection for the first received
// packet, hence might be wrong if packets are not received in order.
// It's up to the caller (e.g. in Accept()) to decide if the direction should
// be interpreted differently.
type TCPFlowDirection bool

// Value are not really useful.
const (
	TCPDirClientToServer TCPFlowDirection = false
	TCPDirServerToClient TCPFlowDirection = true
)

func (dir TCPFlowDirection) String() string {
	switch dir {
	case TCPDirClientToServer:
		return "client->server"
	case TCPDirServerToClient:
		return "server->client"
	}

	return ""
}

// reverse returns the reversed direction.
func (dir TCPFlowDirection) reverse() TCPFlowDirection {
	return !dir
}
