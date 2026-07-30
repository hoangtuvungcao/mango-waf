package detection

import (
	"math"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"mango-waf/config"
	"mango-waf/logger"
)

// Engine is the detection engine
type Engine struct {
	cfg       *config.Config
	baseline  *Baseline
	anomaly   *AnomalyDetector
	rateLimit *AdaptiveRateLimiter
	sessions  *SessionTracker
}

// Baseline tracks normal traffic patterns
type Baseline struct {
	mu            sync.RWMutex
	avgRPS        float64
	stddevRPS     float64
	avgConnPerIP  float64
	stddevConn    float64
	avgReqSize    float64
	p95RPS        float64
	p99RPS        float64
	samples       []float64
	maxSamples    int
	learningUntil time.Time
	isLearning    bool
}

// AnomalyDetector detects anomalous traffic patterns
type AnomalyDetector struct {
	cfg         *config.Config
	baseline    *Baseline
	sensitivity float64
}

// AdaptiveRateLimiter adapts rate limits based on traffic
type AdaptiveRateLimiter struct {
	cfg      *config.Config
	counters sync.Map // map[string]*RateLimitBucket
}

// RateLimitBucket represents a rate limiter for one IP
type RateLimitBucket struct {
	Tokens     float64
	MaxTokens  float64
	RefillRate float64
	LastRefill time.Time
	mu         sync.Mutex
}

// SessionTracker tracks user sessions
type SessionTracker struct {
	sessions sync.Map // map[string]*Session
	ttl      time.Duration
}

// Session represents a tracked user session
type Session struct {
	mu         sync.Mutex
	ID         string
	IP         string
	FirstSeen  time.Time
	LastSeen   time.Time
	Requests   int64
	UniqueURLs map[string]int
	UserAgent  string
	TrustScore float64
	Suspicious bool
}

// NewEngine creates a new detection engine
func NewEngine(cfg *config.Config) *Engine {
	e := &Engine{
		cfg: cfg,
		baseline: &Baseline{
			maxSamples:    3600, // 1 hour of per-second samples
			isLearning:    cfg.Detection.Baseline.Enabled,
			learningUntil: time.Now().Add(cfg.Detection.Baseline.LearningPeriod),
			samples:       make([]float64, 0, 3600),
		},
		anomaly: &AnomalyDetector{
			cfg:         cfg,
			sensitivity: cfg.Detection.Anomaly.Sensitivity,
		},
		rateLimit: &AdaptiveRateLimiter{cfg: cfg},
		sessions:  &SessionTracker{ttl: cfg.Detection.SessionTracking.TTL},
	}
	e.anomaly.baseline = e.baseline

	if cfg.Detection.Baseline.Enabled {
		logger.Info("Detection engine started",
			"learning_period", cfg.Detection.Baseline.LearningPeriod,
			"sensitivity", cfg.Detection.Anomaly.Sensitivity,
		)
	}

	return e
}

// RecordRPSSample records a current RPS sample for baseline learning
func (e *Engine) RecordRPSSample(rps float64) {
	e.baseline.mu.Lock()
	defer e.baseline.mu.Unlock()

	if len(e.baseline.samples) >= e.baseline.maxSamples {
		// Sliding window: remove oldest
		e.baseline.samples = e.baseline.samples[1:]
	}
	e.baseline.samples = append(e.baseline.samples, rps)

	// Recalculate stats
	if len(e.baseline.samples) >= 60 { // Need at least 60 samples
		e.baseline.avgRPS = mean(e.baseline.samples)
		e.baseline.stddevRPS = stddev(e.baseline.samples, e.baseline.avgRPS)
		e.baseline.p95RPS = percentile(e.baseline.samples, 0.95)
		e.baseline.p99RPS = percentile(e.baseline.samples, 0.99)
	}

	// Check if learning period is over
	if e.baseline.isLearning && time.Now().After(e.baseline.learningUntil) {
		e.baseline.isLearning = false
		logger.Info("Baseline learning complete",
			"avg_rps", e.baseline.avgRPS,
			"stddev", e.baseline.stddevRPS,
			"p95", e.baseline.p95RPS,
			"p99", e.baseline.p99RPS,
		)
	}
}

// DetectAnomaly checks if current traffic is anomalous
func (e *Engine) DetectAnomaly(currentRPS float64) *AnomalyResult {
	if e.baseline.isLearning || e.baseline.avgRPS == 0 {
		return &AnomalyResult{IsAnomaly: false, Reason: "learning"}
	}

	result := &AnomalyResult{}

	// Z-score detection
	zScore := (currentRPS - e.baseline.avgRPS) / e.baseline.stddevRPS
	threshold := 3.0 * (1.0 / e.anomaly.sensitivity) // Higher sensitivity = lower threshold

	if zScore > threshold {
		result.IsAnomaly = true
		result.Score = zScore
		result.Reason = "rps_spike"
		result.Severity = classifySeverity(zScore)
	}

	// Percentile-based detection
	if currentRPS > e.baseline.p99RPS*1.5 {
		result.IsAnomaly = true
		result.Score = currentRPS / e.baseline.p99RPS
		result.Reason = "above_p99"
		result.Severity = "high"
	}

	return result
}

// AnomalyResult holds anomaly detection result
type AnomalyResult struct {
	IsAnomaly bool
	Score     float64
	Reason    string
	Severity  string // low, medium, high, critical
}

// CheckRateLimit checks if an IP exceeds rate limits
func (e *Engine) CheckRateLimit(ip string) bool {
	cfg := e.cfg.Protection.RateLimit
	if !cfg.Enabled {
		return false // Not rate limited
	}

	v, _ := e.rateLimit.counters.LoadOrStore(ip, &RateLimitBucket{
		Tokens:     float64(cfg.Burst),
		MaxTokens:  float64(cfg.Burst),
		RefillRate: float64(cfg.RequestsPerSecond),
		LastRefill: time.Now(),
	})

	bucket := v.(*RateLimitBucket)
	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	// Refill tokens
	now := time.Now()
	elapsed := now.Sub(bucket.LastRefill).Seconds()
	bucket.Tokens += elapsed * bucket.RefillRate
	if bucket.Tokens > bucket.MaxTokens {
		bucket.Tokens = bucket.MaxTokens
	}
	bucket.LastRefill = now

	// Adaptive: increase limit for known-good IPs
	if cfg.Adaptive && e.baseline.avgRPS > 0 {
		// During low traffic, be more lenient
		if float64(atomic.LoadInt64(&currentGlobalRPS)) < e.baseline.avgRPS*0.5 {
			bucket.Tokens += 5 // Bonus tokens
		}
	}

	// Try to consume a token
	if bucket.Tokens >= 1 {
		bucket.Tokens--
		return false // Not rate limited
	}

	return true // Rate limited!
}

var currentGlobalRPS int64

// SetGlobalRPS updates the global RPS for adaptive rate limiting
func SetGlobalRPS(rps int64) {
	atomic.StoreInt64(&currentGlobalRPS, rps)
}

// TrackSession tracks a user session
func (e *Engine) TrackSession(ip, url, ua string) *Session {
	if !e.cfg.Detection.SessionTracking.Enabled {
		return nil
	}

	v, loaded := e.sessions.sessions.LoadOrStore(ip, &Session{
		ID:         ip,
		IP:         ip,
		FirstSeen:  time.Now(),
		UniqueURLs: make(map[string]int),
		UserAgent:  ua,
		TrustScore: 50,
	})

	session := v.(*Session)
	session.mu.Lock()
	defer session.mu.Unlock()

	session.LastSeen = time.Now()
	session.Requests++
	if len(session.UniqueURLs) < 20 {
		session.UniqueURLs[url]++
	} else if _, exists := session.UniqueURLs[url]; exists {
		session.UniqueURLs[url]++
	}

	if loaded {
		// Analyze session behavior
		session.analyzeBehavior()
	}

	return session
}

// analyzeBehavior checks for suspicious patterns
func (s *Session) analyzeBehavior() {
	// Very high request count in short time
	elapsed := time.Since(s.FirstSeen).Seconds()
	if elapsed > 0 {
		rps := float64(s.Requests) / elapsed
		if rps > 30 {
			s.Suspicious = true
			s.TrustScore -= 20
		}
	}

	// Very few unique URLs (hammering same endpoint)
	if s.Requests > 100 && len(s.UniqueURLs) < 3 {
		s.Suspicious = true
		s.TrustScore -= 15
	}

	// Clamp
	if s.TrustScore < 0 {
		s.TrustScore = 0
	}
}

// CleanupSessions removes expired sessions
func (e *Engine) CleanupSessions() {
	now := time.Now()
	e.sessions.sessions.Range(func(key, value interface{}) bool {
		session := value.(*Session)
		if now.Sub(session.LastSeen) > e.sessions.ttl {
			e.sessions.sessions.Delete(key)
		}
		return true
	})

	// Clean rate limit buckets
	e.rateLimit.counters.Range(func(key, value interface{}) bool {
		bucket := value.(*RateLimitBucket)
		if time.Since(bucket.LastRefill) > 5*time.Minute {
			e.rateLimit.counters.Delete(key)
		}
		return true
	})
}

// --- Math helpers ---

func mean(data []float64) float64 {
	sum := 0.0
	for _, v := range data {
		sum += v
	}
	return sum / float64(len(data))
}

func stddev(data []float64, avg float64) float64 {
	sum := 0.0
	for _, v := range data {
		diff := v - avg
		sum += diff * diff
	}
	return math.Sqrt(sum / float64(len(data)))
}

func percentile(data []float64, p float64) float64 {
	if len(data) == 0 {
		return 0
	}
	sorted := make([]float64, len(data))
	copy(sorted, data)
	slices.Sort(sorted)
	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}

func classifySeverity(zScore float64) string {
	switch {
	case zScore > 10:
		return "critical"
	case zScore > 6:
		return "high"
	case zScore > 4:
		return "medium"
	default:
		return "low"
	}
}
