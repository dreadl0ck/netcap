package reassembly

import (
	"testing"
	"time"
	"unsafe"
)

func TestSmallOutOfOrderPacketsDoNotRetainFullPayloadPages(t *testing.T) {
	c := newPageCache()
	large := c.next(time.Unix(1, 0))
	c.replace(large)
	var pages []*page
	var retained int
	for i := range 10000 {
		data := []byte{byte(i)}
		lp := livePacket{bytes: data, ac: &assemblerSimpleContext{Timestamp: time.Unix(1, 0)}}
		p, last, count := lp.convertToPages(c, 0, nil)
		data[0] ^= 0xff
		if p != last || count != 1 || len(p.bytes) != 1 || p.bytes[0] != byte(i) {
			t.Fatal("compact page lost owned packet bytes")
		}
		retained += int(unsafe.Sizeof(*p)) + cap(p.buf)
		pages = append(pages, p)
	}
	if retained > 512*len(pages) {
		t.Fatalf("small-packet amplification: %d bytes for %d one-byte payloads", retained, len(pages))
	}
	for _, p := range pages {
		c.replace(p)
	}
	if c.used != 0 || c.size > initialAllocSize {
		t.Fatal("compact pages not released")
	}
}

func TestPageCacheReturnsBurstAllocationsWithoutAnotherPacket(t *testing.T) {
	c := newPageCache()
	pages := make([]*page, 4*initialAllocSize)
	for i := range pages {
		pages[i] = c.next(time.Unix(1, 0))
	}
	for _, p := range pages {
		c.replace(p)
	}
	if c.used != 0 || c.size != initialAllocSize || len(c.free) != c.size {
		t.Fatalf("burst cache retained: size=%d used=%d free=%d", c.size, c.used, len(c.free))
	}
	for _, p := range c.free[len(c.free):cap(c.free)] {
		if p != nil {
			t.Fatal("free-list backing array pins an active or discarded page")
		}
	}
}
