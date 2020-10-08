package utils

import "sync"

// Stats contains statistics about the stream reassembly.
var Stats struct {
	IPdefrag            int64
	MissedBytes         int64
	Pkt                 int64
	Sz                  int64
	Totalsz             int64
	RejectFsm           int64
	RejectOpt           int64
	RejectConnFsm       int64
	Reassembled         int64
	OutOfOrderBytes     int64
	OutOfOrderPackets   int64
	BiggestChunkBytes   int64
	BiggestChunkPackets int64
	OverlapBytes        int64
	OverlapPackets      int64
	SavedTCPConnections int64
	SavedUDPConnections int64
	NumSoftware         int64
	NumServices         int64

	Requests  int64
	Responses int64
	Count     int64
	NumErrors uint
	DataBytes int64
	NumConns  int64
	NumFlows  int64

	// HTTP
	NumUnmatchedResp        int64
	NumNilRequests          int64
	NumFoundRequests        int64
	NumRemovedRequests      int64
	NumUnansweredRequests   int64
	NumClientStreamNotFound int64
	NumRequests             int64
	NumResponses            int64

	sync.Mutex
}
