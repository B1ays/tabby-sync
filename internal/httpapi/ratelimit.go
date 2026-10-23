package httpapi

import (
	"container/list"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// keyedLimiter is a set of token buckets keyed by client network or device.
// The number of buckets is capped so a flood of distinct keys cannot exhaust
// memory. At the cap the least recently used bucket is evicted rather than
// new keys refused: refusing would let anyone with enough addresses lock
// every new client out, while evicting only resets the limit of a key that
// has been quiet the longest. Idle buckets are also dropped by Sweep.
type keyedLimiter struct {
	mu      sync.Mutex
	limit   rate.Limit
	burst   int
	max     int
	idle    time.Duration
	buckets map[string]*list.Element // of *bucket
	lru     *list.List               // most recently used at the front
}

type bucket struct {
	key  string
	lim  *rate.Limiter
	seen time.Time
}

func newKeyedLimiter(perSecond float64, burst int) *keyedLimiter {
	return &keyedLimiter{
		limit:   rate.Limit(perSecond),
		burst:   burst,
		max:     100_000,
		idle:    10 * time.Minute,
		buckets: map[string]*list.Element{},
		lru:     list.New(),
	}
}

func (k *keyedLimiter) get(key string, now time.Time) *rate.Limiter {
	if e, ok := k.buckets[key]; ok {
		b := e.Value.(*bucket)
		b.seen = now
		k.lru.MoveToFront(e)
		return b.lim
	}
	if k.lru.Len() >= k.max {
		oldest := k.lru.Back()
		k.lru.Remove(oldest)
		delete(k.buckets, oldest.Value.(*bucket).key)
	}
	b := &bucket{key: key, lim: rate.NewLimiter(k.limit, k.burst), seen: now}
	k.buckets[key] = k.lru.PushFront(b)
	return b.lim
}

// Allow consumes one token and reports whether it was available.
func (k *keyedLimiter) Allow(key string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := time.Now()
	return k.get(key, now).AllowN(now, 1)
}

// Exhausted reports whether key has no tokens left, without consuming one.
func (k *keyedLimiter) Exhausted(key string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	e, ok := k.buckets[key]
	return ok && e.Value.(*bucket).lim.Tokens() < 1
}

// Sweep drops buckets idle for longer than k.idle, oldest first.
func (k *keyedLimiter) Sweep() {
	k.mu.Lock()
	defer k.mu.Unlock()
	cutoff := time.Now().Add(-k.idle)
	for e := k.lru.Back(); e != nil; e = k.lru.Back() {
		b := e.Value.(*bucket)
		if !b.seen.Before(cutoff) {
			return
		}
		k.lru.Remove(e)
		delete(k.buckets, b.key)
	}
}

// clientKey is the rate-limit key for a client address. An IPv6 client
// usually controls a whole /64, so per-address keys would let one host
// rotate through endless fresh buckets; IPv4 addresses are kept whole.
func clientKey(a netip.Addr) string {
	if a.Is6() && !a.Is4In6() {
		p, err := a.Prefix(64)
		if err == nil {
			return p.String()
		}
	}
	return a.String()
}
