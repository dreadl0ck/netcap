package utils

import "sync"

// Stats contains statistics about the stream reassembly.
var Stats struct {
	sync.Mutex

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
	SavedTCPConnections     int64
	SavedUDPConnections     int64
	SavedNetworkConnections int64
	NumSoftware         int64
	NumServices         int64

	Requests  int64
	Responses int64
	Count     int64
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

	// keep this one after all 64bit types to fix alignment problems on ARM
	NumErrors uint
}

// ResetStats clears all stream reassembly statistics
// This should be called when resetting state between processing different files
func ResetStats() {
	Stats.Lock()
	Stats.IPdefrag = 0
	Stats.MissedBytes = 0
	Stats.Pkt = 0
	Stats.Sz = 0
	Stats.Totalsz = 0
	Stats.RejectFsm = 0
	Stats.RejectOpt = 0
	Stats.RejectConnFsm = 0
	Stats.Reassembled = 0
	Stats.OutOfOrderBytes = 0
	Stats.OutOfOrderPackets = 0
	Stats.BiggestChunkBytes = 0
	Stats.BiggestChunkPackets = 0
	Stats.OverlapBytes = 0
	Stats.OverlapPackets = 0
	Stats.SavedTCPConnections = 0
	Stats.SavedUDPConnections = 0
	Stats.SavedNetworkConnections = 0
	Stats.NumSoftware = 0
	Stats.NumServices = 0
	Stats.Requests = 0
	Stats.Responses = 0
	Stats.Count = 0
	Stats.DataBytes = 0
	Stats.NumConns = 0
	Stats.NumFlows = 0
	Stats.NumUnmatchedResp = 0
	Stats.NumNilRequests = 0
	Stats.NumFoundRequests = 0
	Stats.NumRemovedRequests = 0
	Stats.NumUnansweredRequests = 0
	Stats.NumClientStreamNotFound = 0
	Stats.NumRequests = 0
	Stats.NumResponses = 0
	Stats.NumErrors = 0
	Stats.Unlock()
}
