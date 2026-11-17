package reassembly

import (
	"container/heap"
	"time"
)

// Queued timestamps are independent of TCP sequence order.
type pageDeadlineHeap []*page

func (h pageDeadlineHeap) Len() int           { return len(h) }
func (h pageDeadlineHeap) Less(i, j int) bool { return h[i].seen.Before(h[j].seen) }
func (h pageDeadlineHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].deadlinePosition, h[j].deadlinePosition = i+1, j+1
}
func (h *pageDeadlineHeap) Push(value any) {
	p := value.(*page)
	*h = append(*h, p)
	p.deadlines, p.deadlinePosition = h, len(*h)
}
func (h *pageDeadlineHeap) Pop() any {
	last := len(*h) - 1
	p := (*h)[last]
	(*h)[last] = nil
	*h = (*h)[:last]
	p.deadlines, p.deadlinePosition = nil, 0
	if last == 0 {
		*h = nil
	}
	return p
}
func (p *page) unqueueDeadline() {
	if p.deadlines != nil {
		heap.Remove(p.deadlines, p.deadlinePosition-1)
	}
}
func (h *halfconnection) queueDeadline(p *page) {
	if h.pageDeadlines == nil {
		h.pageDeadlines = new(pageDeadlineHeap)
	}
	heap.Push(h.pageDeadlines, p)
}
func (h *halfconnection) pendingDeadline() (time.Time, bool) {
	if h.closed || h.pageDeadlines == nil || len(*h.pageDeadlines) == 0 {
		return time.Time{}, false
	}
	return (*h.pageDeadlines)[0].seen, true
}
