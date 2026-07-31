package core

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"mango-waf/config"
	"mango-waf/logger"

	"github.com/dgraph-io/ristretto"
)

// CDNManager handles Enterprise Smart Caching
type CDNManager struct {
	cache *ristretto.Cache
	cfg   config.CDNConfig
	stats CDNStats
}

// CDNStats holds caching metrics
type CDNStats struct {
	Hits      int64
	Misses    int64
	Bypasses  int64
	Evictions int64
}

// CachedResponse represents a stored HTTP response
type CachedResponse struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	Expiry     time.Time
}

var globalCDN *CDNManager

// InitCDN initializes the CDN Manager
func InitCDN(cfg config.CDNConfig) error {
	if !cfg.Enabled {
		return nil
	}

	// Calculate NumCounters (10x MaxCost for optimal performance)
	// Assuming an average item size of 50KB: NumCounters = (MemoryLimitMB * 1024 * 1024 / 50000) * 10
	numCounters := int64((cfg.MemoryLimitMB * 1024 * 1024 / 50000) * 10)
	if numCounters < 100000 {
		numCounters = 100000
	}

	cache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: numCounters,
		MaxCost:     int64(cfg.MemoryLimitMB) * 1024 * 1024,
		BufferItems: 64,
		Metrics:     true,
	})
	if err != nil {
		return fmt.Errorf("failed to init ristretto cache: %w", err)
	}

	globalCDN = &CDNManager{
		cache: cache,
		cfg:   cfg,
	}

	logger.Info("CDN Smart Caching enabled", "memory_limit_mb", cfg.MemoryLimitMB)
	return nil
}

// GetCDN returns the global CDN manager instance
func GetCDN() *CDNManager {
	return globalCDN
}

// GetStats returns current CDN metrics
func (cm *CDNManager) GetStats() (int64, int64, int64) {
	if cm == nil {
		return 0, 0, 0
	}
	return atomic.LoadInt64(&cm.stats.Hits), atomic.LoadInt64(&cm.stats.Misses), atomic.LoadInt64(&cm.stats.Bypasses)
}

// GenerateCacheKey creates a unique key for the request using fast string concatenation
func (cm *CDNManager) GenerateCacheKey(r *http.Request) string {
	return r.Method + "_" + r.Host + "_" + r.URL.Path + "_" + r.URL.RawQuery
}

// ShouldBypass checks if the REQUEST should bypass the cache entirely
func (cm *CDNManager) ShouldBypass(r *http.Request) bool {
	// 1. Only cache GET and HEAD methods
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return true
	}

	// 2. Check bypass rules (Paths)
	for _, rule := range cm.cfg.BypassRules {
		if matchBypassRule(r.URL.Path, rule) {
			return true
		}
	}

	// 3. Bypass if specific authorization/authentication headers are present
	if r.Header.Get("Authorization") != "" {
		return true
	}
	for _, h := range cm.cfg.BypassHeaders {
		if r.Header.Get(h) != "" {
			return true
		}
	}

	// 4. Bypass if stateful cookies are present
	cookieHeader := r.Header.Get("Cookie")
	if cookieHeader != "" {
		sensitiveCookies := []string{"session", "logged_in", "phpsessid", "jsessionid", "laravel_session", "csrf"}
		if len(cm.cfg.BypassCookies) > 0 {
			sensitiveCookies = append(sensitiveCookies, cm.cfg.BypassCookies...)
		}

		cookieLower := strings.ToLower(cookieHeader)
		for _, sc := range sensitiveCookies {
			if strings.Contains(cookieLower, strings.ToLower(sc)) {
				return true
			}
		}
	}

	return false
}

// matchBypassRule handles wildcards in bypass rules (e.g., /api/*)
func matchBypassRule(path string, rule string) bool {
	if strings.HasSuffix(rule, "*") {
		prefix := strings.TrimSuffix(rule, "*")
		return strings.HasPrefix(path, prefix)
	}
	return path == rule
}

// IsStaticExtension checks if the path has a configured static extension
func (cm *CDNManager) IsStaticExtension(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == "" {
		return false
	}
	for _, confExt := range cm.cfg.StaticExtensions {
		if ext == confExt {
			return true
		}
	}
	return false
}

// Get retrieves a response from the cache
func (cm *CDNManager) Get(key string) (*CachedResponse, bool) {
	val, found := cm.cache.Get(key)
	if !found {
		atomic.AddInt64(&cm.stats.Misses, 1)
		return nil, false
	}

	resp := val.(*CachedResponse)

	// Check expiry
	if time.Now().After(resp.Expiry) {
		cm.cache.Del(key)
		atomic.AddInt64(&cm.stats.Misses, 1)
		return nil, false
	}

	atomic.AddInt64(&cm.stats.Hits, 1)
	return resp, true
}

// Store saves a response to the cache
func (cm *CDNManager) Store(key string, r *http.Request, resp *http.Response) error {
	// 1. Check if we should cache this response
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	cacheControl := strings.ToLower(resp.Header.Get("Cache-Control"))

	// Do not cache private, no-store, or no-cache responses
	if strings.Contains(cacheControl, "private") ||
		strings.Contains(cacheControl, "no-store") ||
		strings.Contains(cacheControl, "no-cache") {
		return nil
	}

	// Check if backend explicitly set Set-Cookie (Dynamic per-user data)
	if resp.Header.Get("Set-Cookie") != "" {
		return nil
	}

	// Determine TTL
	var ttl time.Duration
	if cm.IsStaticExtension(r.URL.Path) {
		ttl = 24 * time.Hour // Default 24h for configured static assets
	} else if strings.Contains(cacheControl, "public") {
		ttl = 1 * time.Hour // Default 1h for generic public
	} else {
		// Not explicitly static and no public Cache-Control
		return nil
	}

	// 2. Read body with limit to prevent OOM on large files
	limit := int64(5 * 1024 * 1024)
	limitedReader := io.LimitReader(resp.Body, limit+1)
	bodyBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return err
	}

	if len(bodyBytes) == 0 {
		return nil
	}

	if int64(len(bodyBytes)) > limit {
		// Restore body correctly using MultiReader so backend can read it all
		resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(bodyBytes), resp.Body))
		return nil
	}

	// Restore body for the original response to continue processing
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// 3. Store
	cachedResp := &CachedResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header.Clone(),
		Body:       bodyBytes,
		Expiry:     time.Now().Add(ttl),
	}

	cm.cache.SetWithTTL(key, cachedResp, int64(len(bodyBytes)), ttl)
	return nil
}

// RecordBypass increments the bypass counter
func (cm *CDNManager) RecordBypass() {
	atomic.AddInt64(&cm.stats.Bypasses, 1)
}

// Purge removes an item from cache or clears all if key is empty
func (cm *CDNManager) Purge(key string) {
	if cm == nil || cm.cache == nil {
		return
	}
	if key == "" {
		cm.cache.Clear()
	} else {
		cm.cache.Del(key)
	}
}

// ServeFromCache attempts to serve a cached response to the client
func (cm *CDNManager) ServeFromCache(w http.ResponseWriter, r *http.Request) bool {
	if cm == nil || cm.ShouldBypass(r) {
		if cm != nil {
			cm.RecordBypass()
		}
		return false
	}

	key := cm.GenerateCacheKey(r)
	cached, found := cm.Get(key)
	if !found || cached == nil {
		return false
	}

	for k, vals := range cached.Headers {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("X-Mango-Cache", "HIT")
	w.WriteHeader(cached.StatusCode)
	w.Write(cached.Body)
	return true
}
