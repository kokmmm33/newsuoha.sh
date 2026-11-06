package supervisor

import (
	"strings"
	"sync"
	"time"
)

// LogEntry represents a single timestamped log line from xray, cloudflared, or panel.
type LogEntry struct {
	Time    string `json:"time"`
	Source  string `json:"source"` // "xray" | "cloudflared" | "panel"
	Message string `json:"message"`
}

// RingLog stores up to capacity recent log lines in memory.
type RingLog struct {
	mu       sync.RWMutex
	capacity int
	entries  []LogEntry
}

func NewRingLog(capacity int) *RingLog {
	if capacity <= 0 {
		capacity = 300
	}
	return &RingLog{
		capacity: capacity,
		entries:  make([]LogEntry, 0, capacity),
	}
}

func (r *RingLog) Add(source, msg string) {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	entry := LogEntry{
		Time:    time.Now().Format("15:04:05"),
		Source:  source,
		Message: msg,
	}
	if len(r.entries) >= r.capacity {
		copy(r.entries, r.entries[1:])
		r.entries[len(r.entries)-1] = entry
	} else {
		r.entries = append(r.entries, entry)
	}
}

func (r *RingLog) List(source string, limit int) []LogEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if limit <= 0 || limit > r.capacity {
		limit = 150
	}
	var filtered []LogEntry
	for _, e := range r.entries {
		if source == "" || source == "all" || e.Source == source {
			filtered = append(filtered, e)
		}
	}
	if len(filtered) > limit {
		filtered = filtered[len(filtered)-limit:]
	}
	out := make([]LogEntry, len(filtered))
	copy(out, filtered)
	return out
}

func (r *RingLog) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = r.entries[:0]
}
