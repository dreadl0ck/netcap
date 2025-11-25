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

package smb

import (
	"sync"
	"time"

	"go.uber.org/zap"
)

// SMBFileHandle tracks open file handles in SMB sessions
type SMBFileHandle struct {
	FileID       uint64
	Filename     string
	ShareName    string
	SessionID    uint64
	TreeID       uint32
	CreatedAt    time.Time
	AccessMask   uint32
	IsDirectory  bool
}

// SMBFileTracker tracks file handles across SMB sessions
type SMBFileTracker struct {
	mu      sync.RWMutex
	handles map[uint64]*SMBFileHandle // fileID -> handle
}

var globalSMBTracker = &SMBFileTracker{
	handles: make(map[uint64]*SMBFileHandle),
}

// TrackFileHandle records a file handle from SMB CREATE response
func (t *SMBFileTracker) TrackFileHandle(fileID uint64, filename, shareName string, sessionID uint64, treeID uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.handles[fileID] = &SMBFileHandle{
		FileID:    fileID,
		Filename:  filename,
		ShareName: shareName,
		SessionID: sessionID,
		TreeID:    treeID,
		CreatedAt: time.Now(),
	}

	smbLog.Debug("Tracked SMB file handle",
		zap.Uint64("fileID", fileID),
		zap.String("filename", filename),
		zap.String("share", shareName),
	)
}

// GetFileHandle retrieves file information by fileID
func (t *SMBFileTracker) GetFileHandle(fileID uint64) (*SMBFileHandle, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	handle, ok := t.handles[fileID]
	return handle, ok
}

// RemoveFileHandle removes a file handle (on CLOSE)
func (t *SMBFileTracker) RemoveFileHandle(fileID uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.handles, fileID)
	
	smbLog.Debug("Removed SMB file handle",
		zap.Uint64("fileID", fileID),
	)
}

// CleanupExpiredHandles removes stale file handles
func (t *SMBFileTracker) CleanupExpiredHandles() {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	for fileID, handle := range t.handles {
		// Remove handles older than 1 hour
		if now.Sub(handle.CreatedAt) > 1*time.Hour {
			delete(t.handles, fileID)
			smbLog.Debug("Cleaned up expired SMB file handle",
				zap.Uint64("fileID", fileID),
				zap.String("filename", handle.Filename),
			)
		}
	}
}

// Start periodic cleanup
func startSMBCleanup() {
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		for range ticker.C {
			globalSMBTracker.CleanupExpiredHandles()
		}
	}()
}

