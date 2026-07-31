package perf

import (
	"net/http"
	"strings"
	"time"
)

// SecurityHeaders adds security headers to responses
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()

		// Prevent XSS
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-XSS-Protection", "1; mode=block")

		// Prevent clickjacking
		h.Set("X-Frame-Options", "DENY")

		// Force browsers to clear cached HSTS policy for self-signed certificate compatibility
		h.Set("Strict-Transport-Security", "max-age=0")

		// Referrer policy
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Permissions policy
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")

		// Content security policy - allowed jsdelivr for Chart.js fallback
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' blob: cdn.jsdelivr.net https://static.cloudflareinsights.com; worker-src 'self' blob:; style-src 'self' 'unsafe-inline' fonts.googleapis.com; font-src 'self' fonts.gstatic.com; img-src 'self' data:; connect-src 'self' https://static.cloudflareinsights.com")

		// Hide server info
		h.Set("Server", "Mango")
		h.Del("X-Powered-By")

		next.ServeHTTP(w, r)
	})
}

// RequestValidator validates and sanitizes incoming requests
type RequestValidator struct {
	MaxBodySize    int64
	MaxURLLength   int
	MaxHeaderSize  int
	AllowedMethods []string
}

// NewRequestValidator creates a validator with secure defaults
func NewRequestValidator() *RequestValidator {
	return &RequestValidator{
		MaxBodySize:    10 * 1024 * 1024, // 10MB
		MaxURLLength:   8192,
		MaxHeaderSize:  16384,
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"},
	}
}

// Validate validates a request and returns error if invalid
func (v *RequestValidator) Validate(r *http.Request) (bool, string) {
	// Method whitelist
	allowed := false
	for _, m := range v.AllowedMethods {
		if r.Method == m {
			allowed = true
			break
		}
	}
	if !allowed {
		return false, "method_not_allowed"
	}

	// URL length & null byte check using pre-allocated RequestURI (falls back to URL.String in unit tests)
	uri := r.RequestURI
	if uri == "" {
		uri = r.URL.String()
	}
	if len(uri) > v.MaxURLLength {
		return false, "url_too_long"
	}
	if strings.Contains(uri, "\x00") {
		return false, "null_byte_url"
	}

	// Request body size
	if r.ContentLength > v.MaxBodySize {
		return false, "body_too_large"
	}

	// Header count
	totalHeaderSize := 0
	for name, values := range r.Header {
		totalHeaderSize += len(name)
		for _, v := range values {
			totalHeaderSize += len(v)
		}
	}
	if totalHeaderSize > v.MaxHeaderSize {
		return false, "headers_too_large"
	}

	// Host header present
	if r.Host == "" {
		return false, "missing_host"
	}

	return true, ""
}

// GracefulDegrader manages graceful degradation under load
type GracefulDegrader struct {
	thresholds []DegradationLevel
	current    int
}

// DegradationLevel defines a degradation tier
type DegradationLevel struct {
	Name            string
	RPSThreshold    int64
	DisableFeatures []string // Features to disable at this level
	RateLimitFactor float64  // Multiplier for rate limits
}

// NewGracefulDegrader creates a degrader with default levels
func NewGracefulDegrader() *GracefulDegrader {
	return &GracefulDegrader{
		thresholds: []DegradationLevel{
			{
				Name:            "normal",
				RPSThreshold:    0,
				DisableFeatures: nil,
				RateLimitFactor: 1.0,
			},
			{
				Name:            "elevated",
				RPSThreshold:    500,
				DisableFeatures: []string{"detailed_logging", "slow_queries"},
				RateLimitFactor: 0.8,
			},
			{
				Name:            "high",
				RPSThreshold:    2000,
				DisableFeatures: []string{"detailed_logging", "slow_queries", "reputation_lookup", "geo_lookup"},
				RateLimitFactor: 0.5,
			},
			{
				Name:            "critical",
				RPSThreshold:    5000,
				DisableFeatures: []string{"detailed_logging", "slow_queries", "reputation_lookup", "geo_lookup", "waf_deep_inspect", "behavioral_analysis"},
				RateLimitFactor: 0.2,
			},
			{
				Name:            "survival",
				RPSThreshold:    10000,
				DisableFeatures: []string{"all_optional"},
				RateLimitFactor: 0.1,
			},
		},
	}
}

// Evaluate determines the current degradation level based on RPS
func (gd *GracefulDegrader) Evaluate(currentRPS int64) *DegradationLevel {
	level := &gd.thresholds[0]
	for i := len(gd.thresholds) - 1; i >= 0; i-- {
		if currentRPS >= gd.thresholds[i].RPSThreshold {
			level = &gd.thresholds[i]
			break
		}
	}
	return level
}

// IsFeatureDisabled checks if a feature should be disabled at current level
func (gd *GracefulDegrader) IsFeatureDisabled(feature string, currentRPS int64) bool {
	level := gd.Evaluate(currentRPS)
	for _, f := range level.DisableFeatures {
		if f == feature || f == "all_optional" {
			return true
		}
	}
	return false
}

// ================================================
// Request Timing Middleware
// ================================================

// TimingMiddleware adds request timing headers
func TimingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		elapsed := time.Since(start)
		w.Header().Set("X-Response-Time", elapsed.String())
		w.Header().Set("X-Served-By", "Mango-Shield/2.0")
	})
}
