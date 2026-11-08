// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package reassembly

import (
	"log"
	"time"
)

/*
 * pageCache
 */
// pageCache is a concurrency-unsafe store of page objects we use to avoid
// memory allocation as much as we can.
type pageCache struct {
	budget       *PageBudget
	free         []*page
	pcSize       int
	size, used   int
	pageRequests int64
	ops          int
	nextShrink   int
}

const initialAllocSize = 1024

func newPageCache() *pageCache {
	return &pageCache{pcSize: initialAllocSize}
}

// grow exponentially increases the size of our page cache as much as necessary.
func (c *pageCache) grow() {
	if c.free == nil {
		c.free = make([]*page, 0, c.pcSize)
	}
	pages := make([]page, c.pcSize)
	c.size += c.pcSize
	for i := range pages {
		c.free = append(c.free, &pages[i])
	}
	if Debug {
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
	minimum := max(c.pcSize/2, initialAllocSize)

	if len(c.free) <= minimum {
		return
	}

	for i := range c.free[minimum:] {
		c.free[minimum+i] = nil
	}

	c.size -= len(c.free) - minimum
	c.free = c.free[:minimum]
	c.pcSize = minimum
}

// next returns a clean, ready-to-use page object.
func (c *pageCache) next(ts time.Time) (p *page) {
	if c.budget != nil {
		c.used++
		c.size++
		p = &page{seen: ts}
		p.bytes = p.buf[:0]
		return p
	}
	if Debug {
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
	if Debug {
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
	if c.budget != nil {
		c.size--
		*p = page{}
		c.budget.release()
		return
	}
	if Debug {
		log.Printf("replacing %s\n", p)
	}
	p.prev = nil
	p.next = nil
	p.ac = nil
	c.free = append(c.free, p)
}
