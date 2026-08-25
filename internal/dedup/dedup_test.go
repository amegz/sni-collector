package dedup

import (
	"testing"
	"time"
)

func TestSeenSuppressesWithinTTL(t *testing.T) {
	c := New(time.Hour)
	now := time.Now()
	c.now = func() time.Time { return now }

	if c.Seen("host-a|example.com") {
		t.Fatalf("first sighting should not be reported as seen")
	}
	if !c.Seen("host-a|example.com") {
		t.Fatalf("repeat within TTL should be reported as seen")
	}
}

func TestSeenAllowsAgainAfterTTL(t *testing.T) {
	c := New(time.Minute)
	now := time.Now()
	c.now = func() time.Time { return now }

	if c.Seen("k") {
		t.Fatalf("first sighting should not be seen")
	}
	now = now.Add(2 * time.Minute)
	if c.Seen("k") {
		t.Fatalf("sighting after TTL expiry should not be reported as seen")
	}
}

func TestSweepRemovesExpiredEntries(t *testing.T) {
	c := New(time.Minute)
	now := time.Now()
	c.now = func() time.Time { return now }

	c.Seen("a")
	c.Seen("b")
	if got := c.Len(); got != 2 {
		t.Fatalf("Len() = %d, want 2", got)
	}

	now = now.Add(2 * time.Minute)
	c.Sweep()
	if got := c.Len(); got != 0 {
		t.Fatalf("Len() after sweep = %d, want 0", got)
	}
}

func TestDistinctKeysNotConflated(t *testing.T) {
	c := New(time.Hour)
	if c.Seen("host-a|example.com") {
		t.Fatalf("first sighting of key A should not be seen")
	}
	if c.Seen("host-b|example.com") {
		t.Fatalf("first sighting of key B (different source) should not be seen")
	}
}
