package tcp

func (f *connectionFactory) readerSnapshot() []streamReader {
	f.Lock()
	defer f.Unlock()
	readers := make([]streamReader, 0, len(f.streamReaders)-len(f.freeReaderSlots))
	for _, reader := range f.streamReaders {
		if reader != nil {
			readers = append(readers, reader)
		}
	}
	return readers
}

// Finalized connections retain their FSM metadata, not reader tasks or payload stores.
func (t *tcpConnection) releaseResources() {
	if t.factory == nil {
		return
	}
	t.releasePayloadAdmission()
	t.releaseOnce.Do(func() {
		if t.incremental != nil {
			t.incremental.Abort()
		}
		readers := []streamReader{t.client, t.server}
		for _, reader := range readers {
			if reader != nil {
				reader.CloseData()
			}
		}
		for _, reader := range readers {
			if owned, ok := reader.(*tcpStreamReader); ok && owned.done != nil {
				<-owned.done
			}
		}
		t.Lock()
		for _, reader := range readers {
			if owned, ok := reader.(*tcpStreamReader); ok {
				owned.data = nil
				owned.storedMarkers = nil
				if owned.stored != nil {
					_ = owned.stored.clear()
				}
			}
		}
		t.merged, t.decoder = nil, nil
		t.resourcesReleased = true
		t.incrementalBanner = nil
		clear(t.retentionMarkers[:])
		clear(t.pageBudgetMarkers[:])
		clear(t.postCloseMarkers[:])
		if t.payloadBudget != nil {
			t.payloadBudget.release(t.retainedPayloadBytes)
			t.retainedPayloadBytes = 0
		}
		t.Unlock()
		t.factory.Lock()
		defer t.factory.Unlock()
		for _, reader := range readers {
			if owned, ok := reader.(*tcpStreamReader); ok && owned.factorySlot >= 0 && t.factory.streamReaders[owned.factorySlot] == reader {
				t.factory.streamReaders[owned.factorySlot] = nil
				t.factory.freeReaderSlots = append(t.factory.freeReaderSlots, owned.factorySlot)
				owned.factorySlot = -1
			}
		}
	})
}

func (t *tcpConnection) releasePayloadAdmission() {
	if t.factory == nil {
		return
	}
	t.factory.Lock()
	defer t.factory.Unlock()
	if t.payloadAdmission {
		t.payloadAdmission = false
		t.factory.pendingPayloads--
	}
}
