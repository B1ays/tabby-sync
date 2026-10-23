package httpapi

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// keyedLimiter is a set of token buckets keyed by client IP or device.
// Idle buckets are dropped by Sweep. The number of buckets is capped so a
// flood of distinct keys cannot exhaust memory; past the cap new keys are
// refused until idle ones expire.
type keyedLimiter struct {
	mu      sync.Mutex
	limit   rate.Limit
	burst   int
	max     int
	idle    time.Duration
	buckets map[string]*bucket
}

type bucket struct {
	lim  *rate.Limiter
	seen time.Time
}

func newKeyedLimiter(perSecond float64, burst int) *keyedLimiter {
	return &keyedLimiter{
		limit:   rate.Limit(perSecond),
		burst:   burst,
		max:     100_000,
		idle:    10 * time.Minute,
		buckets: map[string]*bucket{},
	}
}

func (k *keyedLimiter) get(key string, now time.Time) *rate.Limiter {
	b, ok := k.buckets[key]
	if !ok {
		if len(k.buckets) >= k.max {
			return nil
		}
		b = &bucket{lim: rate.NewLimiter(k.limit, k.burst)}
		k.buckets[key] = b
	}
	b.seen = now
	return b.lim
}

// Allow consumes one token and reports whether it was available.
func (k *keyedLimiter) Allow(key string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := time.Now()
	lim := k.get(key, now)
	return lim != nil && lim.AllowN(now, 1)
}

// Exhausted reports whether key has no tokens left, without consuming one.
func (k *keyedLimiter) Exhausted(key string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	b, ok := k.buckets[key]
	return ok && b.lim.Tokens() < 1
}

func (k *keyedLimiter) Sweep() {
	k.mu.Lock()
	defer k.mu.Unlock()
	cutoff := time.Now().Add(-k.idle)
	for key, b := range k.buckets {
		if b.seen.Before(cutoff) {
			delete(k.buckets, key)
		}
	}
}
