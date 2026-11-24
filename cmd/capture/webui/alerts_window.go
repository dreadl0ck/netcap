package webui

import (
	"container/heap"
	"encoding/json"
	"fmt"
	"sort"
)

const (
	// maxAlertListWindow bounds offset+limit of the alert list, so a page
	// never holds more than this many alerts while streaming the audit.
	maxAlertListWindow = 5_000
	// alertListBudgetBytes bounds the encoded alerts a list or group view holds.
	alertListBudgetBytes = 64 << 20
	// maxGroupUniqueValues bounds each unique IP/port list of a group.
	maxGroupUniqueValues = 256
)

type windowedAlert struct {
	alert AlertResponse
	size  int
}

// alertWindow keeps the first n alerts of the requested order while the
// audit streams past, instead of reading and sorting the whole audit.
type alertWindow struct {
	items     []windowedAlert
	n         int
	ascending bool
	remaining int
}

func newAlertWindow(n int, ascending bool, budget int) *alertWindow {
	return &alertWindow{n: n, ascending: ascending, remaining: budget}
}

// before reports whether a sorts before b in the requested order; ties break
// on the alert ID so pages are stable.
func (w *alertWindow) before(a, b *AlertResponse) bool {
	if a.Timestamp != b.Timestamp {
		return (a.Timestamp < b.Timestamp) == w.ascending
	}
	return a.AlertID < b.AlertID
}

// The heap's root is the alert that would leave the window first.
func (w *alertWindow) Len() int           { return len(w.items) }
func (w *alertWindow) Less(i, j int) bool { return w.before(&w.items[j].alert, &w.items[i].alert) }
func (w *alertWindow) Swap(i, j int)      { w.items[i], w.items[j] = w.items[j], w.items[i] }
func (w *alertWindow) Push(x any)         { w.items = append(w.items, x.(windowedAlert)) }
func (w *alertWindow) Pop() any {
	last := w.items[len(w.items)-1]
	w.items = w.items[:len(w.items)-1]
	return last
}

func (w *alertWindow) add(alert AlertResponse) error {
	if w.n <= 0 {
		return nil
	}
	if len(w.items) == w.n && !w.before(&alert, &w.items[0].alert) {
		return nil
	}
	raw, err := json.Marshal(alert)
	if err != nil {
		return err
	}
	size := len(raw) + 256
	if len(w.items) == w.n {
		w.remaining += heap.Pop(w).(windowedAlert).size
	}
	if size > w.remaining {
		return fmt.Errorf("%w: alert page exceeds %d bytes; use a smaller limit", errAlertPageSourceLimit, alertListBudgetBytes)
	}
	w.remaining -= size
	heap.Push(w, windowedAlert{alert: alert, size: size})
	return nil
}

func (w *alertWindow) sorted() []AlertResponse {
	out := make([]AlertResponse, len(w.items))
	for i := range w.items {
		out[i] = w.items[i].alert
	}
	sort.Slice(out, func(i, j int) bool { return w.before(&out[i], &out[j]) })
	return out
}
