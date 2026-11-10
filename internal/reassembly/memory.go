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
	size, used   int
	pageRequests int64
}

const initialAllocSize = 1024

func newPageCache() *pageCache {
	return &pageCache{}
}

// Pages own separate allocations so one live page cannot pin an entire slab.
func (c *pageCache) grow() {
	if c.free == nil {
		c.free = make([]*page, 0, initialAllocSize)
	}
	c.size += initialAllocSize
	for range initialAllocSize {
		c.free = append(c.free, new(page))
	}
	if Debug {
		log.Println("PageCache: created", initialAllocSize, "new pages, size:", c.size, "cap:", cap(c.free), "len:", len(c.free))
	}
}

// next returns a clean, ready-to-use page object.
func (c *pageCache) next(ts time.Time, sizes ...int) (p *page) {
	size := pageBytes
	if len(sizes) > 0 {
		size = min(pageBytes, max(0, sizes[0]))
	}
	prepare := func(p *page) *page {
		if cap(p.buf) < size || cap(p.buf) > max(64, 2*size) {
			p.buf = make([]byte, size)
		}
		p.buf = p.buf[:size]
		p.seen, p.bytes = ts, p.buf[:0]
		return p
	}
	if c.budget != nil {
		c.used++
		c.size++
		return prepare(new(page))
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
	p = c.free[i]
	c.free[i] = nil
	c.free = c.free[:i]
	prepare(p)
	c.used++
	if Debug {
		log.Printf("allocator returns %s\n", p)
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
	if len(c.free) >= initialAllocSize {
		c.size--
		return
	}
	c.free = append(c.free, p)
}
