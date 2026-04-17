package goauth

import (
	"sync"
	"time"
)

// loginRateLimiter enforces two independent sliding-window limits:
//
//   - Per source IP:  maxPerIP attempts within windowIP
//   - Per username:   maxPerUser attempts within windowUser
//
// Both must pass for a login attempt to proceed. Counters are kept
// in-memory and pruned periodically — no database writes on the hot path.
type loginRateLimiter struct {
	mu         sync.Mutex
	byIP       map[string][]time.Time
	byUser     map[string][]time.Time
	windowIP   time.Duration
	windowUser time.Duration
	maxPerIP   int
	maxPerUser int
}

func newLoginRateLimiter() *loginRateLimiter {
	rl := &loginRateLimiter{
		byIP:       make(map[string][]time.Time),
		byUser:     make(map[string][]time.Time),
		windowIP:   time.Minute,
		windowUser: 10 * time.Minute,
		maxPerIP:   10, // 10 attempts / min per IP
		maxPerUser: 20, // 20 attempts / 10 min per username
	}
	go rl.cleanup(5 * time.Minute)
	return rl
}

// Allow returns (allowed, retryAfter).
// retryAfter is only meaningful when allowed == false.
// ip should be the real client IP (after XFF resolution).
// username may be empty if the request body couldn't be parsed.
func (rl *loginRateLimiter) Allow(ip, username string) (bool, time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// ── Per-IP check ──────────────────────────────────────────────────────────
	rl.byIP[ip] = recentTimestamps(rl.byIP[ip], rl.windowIP, now)
	if len(rl.byIP[ip]) >= rl.maxPerIP {
		oldest := rl.byIP[ip][0]
		retryAfter := rl.windowIP - now.Sub(oldest)
		return false, retryAfter
	}
	rl.byIP[ip] = append(rl.byIP[ip], now)

	// ── Per-username check ────────────────────────────────────────────────────
	if username != "" {
		key := "u:" + username
		rl.byUser[key] = recentTimestamps(rl.byUser[key], rl.windowUser, now)
		if len(rl.byUser[key]) >= rl.maxPerUser {
			oldest := rl.byUser[key][0]
			retryAfter := rl.windowUser - now.Sub(oldest)
			return false, retryAfter
		}
		rl.byUser[key] = append(rl.byUser[key], now)
	}

	return true, 0
}

// recentTimestamps filters a slice of timestamps to only those within window.
func recentTimestamps(ts []time.Time, window time.Duration, now time.Time) []time.Time {
	cutoff := now.Add(-window)
	out := ts[:0]
	for _, t := range ts {
		if t.After(cutoff) {
			out = append(out, t)
		}
	}
	return out
}

// cleanup runs periodically and removes stale entries to prevent unbounded growth.
func (rl *loginRateLimiter) cleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, ts := range rl.byIP {
			rl.byIP[ip] = recentTimestamps(ts, rl.windowIP, now)
			if len(rl.byIP[ip]) == 0 {
				delete(rl.byIP, ip)
			}
		}
		for u, ts := range rl.byUser {
			rl.byUser[u] = recentTimestamps(ts, rl.windowUser, now)
			if len(rl.byUser[u]) == 0 {
				delete(rl.byUser, u)
			}
		}
		rl.mu.Unlock()
	}
}
