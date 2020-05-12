// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package reassembly

import (
	"flag"
	"log"
	"time"
)

var memLog = flag.Bool("assembly_memuse_log", defaultDebug, "If true, the github.com/dreadl0ck/gopacket/reassembly library will log information regarding its memory use every once in a while.")

/*
 * pageCache
 */
// pageCache is a concurrency-unsafe store of page objects we use to avoid
// memory allocation as much as we can.
type pageCache struct {
	free         []*page
	pcSize       int
	size, used   int
	pageRequests int64
	ops          int
	nextShrink   int
}

const initialAllocSize = 1024

func newPageCache() *pageCache {
	pc := &pageCache{
		free:   make([]*page, 0, initialAllocSize),
		pcSize: initialAllocSize,
	}
	pc.grow()
	return pc
}

// grow exponentially increases the size of our page cache as much as necessary.
func (c *pageCache) grow() {
	pages := make([]page, c.pcSize)
	c.size += c.pcSize
	for i := range pages {
		c.free = append(c.free, &pages[i])
	}
	if *memLog {
		log.Println("PageCache: created", c.pcSize, "new pages, size:", c.size, "cap:", cap(c.free), "len:", len(c.free))
	}
	// control next shrink attempt
	c.nextShrink = c.pcSize
	c.ops = 0
	// prepare for next alloc
	c.pcSize *= 2
}

// Remove references to unused pages to let GC collect them
// Note: memory used by c.free itself it not collected.
func (c *pageCache) tryShrink() {
	var min = c.pcSize / 2
	if min < initialAllocSize {
		min = initialAllocSize
	}
	if len(c.free) <= min {
		return
	}
	for i := range c.free[min:] {
		c.free[min+i] = nil
	}
	c.size -= len(c.free) - min
	c.free = c.free[:min]
	c.pcSize = min
}

// next returns a clean, ready-to-use page object.
func (c *pageCache) next(ts time.Time) (p *page) {
	if *memLog {
		c.pageRequests++
		if c.pageRequests&0xFFFF == 0 {
			log.Println("PageCache:", c.pageRequests, "requested,", c.used, "used,", len(c.free), "free")
		}
	}
	if len(c.free) == 0 {
		c.grow()
	}
	i := len(c.free) - 1
	p, c.free = c.free[i], c.free[:i]
	p.seen = ts
	p.bytes = p.buf[:0]
	c.used++
	if *memLog {
		log.Printf("allocator returns %s\n", p)
	}
	c.ops++
	if c.ops > c.nextShrink {
		c.ops = 0
		c.tryShrink()
	}

	return p
}

// replace replaces a page into the pageCache.
func (c *pageCache) replace(p *page) {
	c.used--
	if *memLog {
		log.Printf("replacing %s\n", p)
	}
	p.prev = nil
	p.next = nil
	c.free = append(c.free, p)
}
