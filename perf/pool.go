package perf

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"mango-waf/logger"
)

// ConnectionPool manages a pool of reusable backend connections
type ConnectionPool struct {
	maxIdle     int
	maxOpen     int
	idleTimeout time.Duration
	active      int64
	idle        int64
	totalOpened int64
	totalClosed int64
	waitCount   int64
}

// NewConnectionPool creates a new connection pool
func NewConnectionPool(maxIdle, maxOpen int) *ConnectionPool {
	return &ConnectionPool{
		maxIdle:     maxIdle,
		maxOpen:     maxOpen,
		idleTimeout: 90 * time.Second,
	}
}

// Stats returns pool statistics
func (p *ConnectionPool) Stats() map[string]int64 {
	return map[string]int64{
		"active":       atomic.LoadInt64(&p.active),
		"idle":         atomic.LoadInt64(&p.idle),
		"total_opened": atomic.LoadInt64(&p.totalOpened),
		"total_closed": atomic.LoadInt64(&p.totalClosed),
		"waits":        atomic.LoadInt64(&p.waitCount),
	}
}

// ================================================
// Token Bucket Rate Limiter
// ================================================

// TokenBucket implements a token bucket rate limiter
type TokenBucket struct {
	mu       sync.Mutex
	tokens   float64
	capacity float64
	rate     float64 // tokens per second
	lastTime time.Time
}

// NewTokenBucket creates a new token bucket
func NewTokenBucket(rate float64, capacity float64) *TokenBucket {
	return &TokenBucket{
		tokens:   capacity,
		capacity: capacity,
		rate:     rate,
		lastTime: time.Now(),
	}
}

// Allow checks if a request is allowed
func (tb *TokenBucket) Allow() bool {
	return tb.AllowN(1)
}

// AllowN checks if N tokens are available
func (tb *TokenBucket) AllowN(n float64) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastTime).Seconds()
	tb.tokens += elapsed * tb.rate
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}
	tb.lastTime = now

	if tb.tokens >= n {
		tb.tokens -= n
		return true
	}
	return false
}

// SetRate dynamically updates the rate
func (tb *TokenBucket) SetRate(newRate float64) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.rate = newRate
}

// LastSeen returns the last access timestamp
func (tb *TokenBucket) LastSeen() time.Time {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return tb.lastTime
}

// IPRateLimiter manages per-IP rate limiters
type IPRateLimiter struct {
	mu       sync.RWMutex
	limiters map[string]*TokenBucket
	rate     float64
	capacity float64
}

// NewIPRateLimiter creates a new per-IP rate limiter
func NewIPRateLimiter(rps float64, burst float64) *IPRateLimiter {
	rl := &IPRateLimiter{
		limiters: make(map[string]*TokenBucket),
		rate:     rps,
		capacity: burst,
	}
	go rl.cleanupLoop()
	return rl
}

// Allow checks if an IP's request is allowed
func (rl *IPRateLimiter) Allow(ip string) bool {
	rl.mu.RLock()
	limiter, ok := rl.limiters[ip]
	rl.mu.RUnlock()

	if !ok {
		rl.mu.Lock()
		// Double-check
		limiter, ok = rl.limiters[ip]
		if !ok {
			limiter = NewTokenBucket(rl.rate, rl.capacity)
			rl.limiters[ip] = limiter
		}
		rl.mu.Unlock()
	}

	return limiter.Allow()
}

// SetGlobalRate updates rate for all new limiters
func (rl *IPRateLimiter) SetGlobalRate(rps float64) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.rate = rps
}

// SetRate updates both rate and capacity dynamically
func (rl *IPRateLimiter) SetRate(rps float64, burst float64) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rps > 0 {
		rl.rate = rps
	}
	if burst > 0 {
		rl.capacity = burst
	}
}

func (rl *IPRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		rl.mu.Lock()
		for ip, tb := range rl.limiters {
			if now.Sub(tb.LastSeen()) > 10*time.Minute {
				delete(rl.limiters, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// ================================================
// Memory Manager
// ================================================

// MemoryManager monitors and controls memory usage
type MemoryManager struct {
	maxMemoryMB  int64
	gcThreshold  float64 // trigger GC at this % of max
	lastGC       time.Time
	forceGCCount int64
}

// NewMemoryManager creates a new memory manager
func NewMemoryManager(maxMB int64) *MemoryManager {
	mm := &MemoryManager{
		maxMemoryMB: maxMB,
		gcThreshold: 0.8,
	}
	go mm.monitorLoop()
	return mm
}

func (mm *MemoryManager) monitorLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		allocMB := int64(m.Alloc / 1024 / 1024)
		sysMB := int64(m.Sys / 1024 / 1024)

		// Force GC if above threshold
		if mm.maxMemoryMB > 0 && allocMB > int64(float64(mm.maxMemoryMB)*mm.gcThreshold) {
			runtime.GC()
			atomic.AddInt64(&mm.forceGCCount, 1)
			logger.Warn("Force GC triggered",
				"alloc_mb", allocMB,
				"sys_mb", sysMB,
				"max_mb", mm.maxMemoryMB,
			)
		}
	}
}

// GetMemStats returns current memory statistics
func (mm *MemoryManager) GetMemStats() map[string]interface{} {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return map[string]interface{}{
		"alloc_mb":      m.Alloc / 1024 / 1024,
		"sys_mb":        m.Sys / 1024 / 1024,
		"heap_objects":  m.HeapObjects,
		"gc_runs":       m.NumGC,
		"force_gc":      atomic.LoadInt64(&mm.forceGCCount),
		"goroutines":    runtime.NumGoroutine(),
		"max_memory_mb": mm.maxMemoryMB,
	}
}

// ================================================
// Object Pool for Request Context
// ================================================

// RequestContext pools reusable request context objects
type RequestContext struct {
	IP          string
	URL         string
	Method      string
	UserAgent   string
	Headers     map[string]string
	TrustScore  float64
	Fingerprint interface{}
	StartTime   time.Time
}

var requestCtxPool = sync.Pool{
	New: func() interface{} {
		return &RequestContext{
			Headers: make(map[string]string, 16),
		}
	},
}

// AcquireRequestContext gets a request context from the pool
func AcquireRequestContext() *RequestContext {
	ctx := requestCtxPool.Get().(*RequestContext)
	ctx.StartTime = time.Now()
	return ctx
}

// ReleaseRequestContext returns a request context to the pool
func ReleaseRequestContext(ctx *RequestContext) {
	ctx.IP = ""
	ctx.URL = ""
	ctx.Method = ""
	ctx.UserAgent = ""
	ctx.TrustScore = 0
	ctx.Fingerprint = nil
	for k := range ctx.Headers {
		delete(ctx.Headers, k)
	}
	requestCtxPool.Put(ctx)
}
