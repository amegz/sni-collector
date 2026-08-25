// Package dedup implements a small TTL-based "have I seen this key
// recently" cache used to suppress repeated log lines for the same
// (source IP, SNI) pair.
package dedup

import (
	"sync"
	"time"
)

// Cache tracks the last time each key was seen and reports keys as
// duplicates until ttl has elapsed since that last sighting.
//
// Safe for concurrent use.
type Cache struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]time.Time
	now     func() time.Time
}

// New creates a Cache with the given TTL. A zero or negative ttl means
// entries never expire (every repeat is treated as new only once per
// process restart — use Seen accordingly).
func New(ttl time.Duration) *Cache {
	return &Cache{
		ttl:     ttl,
		entries: make(map[string]time.Time),
		now:     time.Now,
	}
}

// Seen reports whether key was already recorded within the TTL window.
// If it wasn't (first sighting, or the previous sighting has expired), it
// records key as seen now and returns false.
func (c *Cache) Seen(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	if last, ok := c.entries[key]; ok {
		if c.ttl <= 0 || now.Sub(last) < c.ttl {
			return true
		}
	}
	c.entries[key] = now
	return false
}

// Sweep drops entries whose TTL has expired, bounding memory growth for a
// long-running process. It is a no-op when ttl <= 0.
func (c *Cache) Sweep() {
	if c.ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	for k, t := range c.entries {
		if now.Sub(t) >= c.ttl {
			delete(c.entries, k)
		}
	}
}

// Len returns the number of tracked keys (including possibly-expired ones
// not yet swept). Mainly useful for tests and diagnostics.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
