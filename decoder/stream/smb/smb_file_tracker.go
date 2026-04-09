/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package smb

import (
	"sync"
	"time"

	"go.uber.org/zap"
)

// SMBFileHandle tracks open file handles in SMB sessions
type SMBFileHandle struct {
	FileID      uint64
	Filename    string
	ShareName   string
	SessionID   uint64
	TreeID      uint32
	CreatedAt   time.Time
	AccessMask  uint32
	IsDirectory bool
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
