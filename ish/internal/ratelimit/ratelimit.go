package ratelimit

import (
	"sync"
	"time"
)

// bucket is a simple token-bucket rate limiter.
type bucket struct {
	tokens    int
	last      time.Time
	lastAllow time.Time
}

// Limiter limits requests per IP using a token-bucket algorithm.
// Buckets are created lazily and stale empty buckets are cleaned up
// periodically to avoid unbounded memory growth.
type Limiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     time.Duration // time between token refills
	burst    int
	maxIdle  time.Duration
	lastClean time.Time
}

// New creates a rate limiter that allows burst requests per IP, refilling one
// token every rate interval. maxIdle controls how long a bucket with zero
// tokens can remain in memory before being dropped.
func New(rate time.Duration, burst int, maxIdle time.Duration) *Limiter {
	return &Limiter{
		buckets:   make(map[string]*bucket),
		rate:      rate,
		burst:     burst,
		maxIdle:   maxIdle,
		lastClean: time.Now(),
	}
}

// Allow reports whether a request from the given key is allowed right now.
func (l *Limiter) Allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst - 1, last: now, lastAllow: now}
		l.buckets[key] = b
		return true
	}

	elapsed := now.Sub(b.last)
	if elapsed >= l.rate && b.tokens < l.burst {
		add := int(elapsed / l.rate)
		if add > l.burst-b.tokens {
			add = l.burst - b.tokens
		}
		b.tokens += add
		b.last = now
	}

	if b.tokens > 0 {
		b.tokens--
		b.lastAllow = now
		return true
	}

	if now.Sub(l.lastClean) > l.maxIdle {
		l.cleanupLocked(now)
		l.lastClean = now
	}
	return false
}

func (l *Limiter) cleanupLocked(now time.Time) {
	for k, b := range l.buckets {
		if now.Sub(b.lastAllow) > l.maxIdle && b.tokens == 0 {
			delete(l.buckets, k)
		}
	}
}
