package core

import (
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mango-waf/cluster"
	"mango-waf/config"
	"mango-waf/detection"
	"mango-waf/fingerprint"
	"mango-waf/intelligence"
	"mango-waf/logger"
	"mango-waf/perf"
	"mango-waf/rules"
)

// ActionType represents the decision made by the pipeline
type ActionType int

const (
	ActionAllow ActionType = iota
	ActionChallenge
	ActionBlock
	ActionRateLimit
	ActionDrop
)

// Action is the result of pipeline processing
type Action struct {
	Type       ActionType
	Reason     string
	Stage      int
	Difficulty int
}

// Pre-computed stage name strings (zero allocation in hotpath)
var stageNames = [...]string{"stage_0", "stage_1", "stage_2", "stage_3", "stage_4", "stage_5", "stage_6"}

// Pre-compiled bad user-agent set (zero allocation per request)
var badUASet map[string]struct{}

func init() {
	agents := []string{
		"curl", "wget", "python", "java", "go-http-client",
		"node-fetch", "axios", "httpie", "scrapy",
		"crawler", "spider", "scan", "masscan", "nikto",
		"sqlmap", "nmap", "dirbuster", "gobuster",
	}
	badUASet = make(map[string]struct{}, len(agents))
	for _, a := range agents {
		badUASet[a] = struct{}{}
	}
}

// Pipeline is the request processing pipeline
type Pipeline struct {
	shield        *Shield
	cfg           *config.Config
	domainModeMap map[string]string // domain -> protection_mode (pre-lowercased keys)
	validHostMap  map[string]bool   // pre-lowercased domain names for O(1) host validation
	ipStates      *IPStateMap       // 256-shard high-concurrency map
	banned        sync.Map          // map[string]time.Time
	whitelist     sync.Map          // map[string]time.Time
	alerts        *AlertManager
	intel         *intelligence.Intel
	detEngine     *detection.Engine
	behavior      *detection.BehaviorAnalyzer
	botClass      *detection.BotClassifier
	attackDet     *detection.AttackDetector
	adaptive      *detection.AdaptiveLearner
	wafEngine     *rules.Engine
	rateLimiter   *perf.IPRateLimiter
	degrader      *perf.GracefulDegrader
	validator     *perf.RequestValidator
	xdpMgr        *XDPManager
}

// IPState tracks per-IP behavior
type IPState struct {
	mu               sync.Mutex
	RequestCount     int64
	RPS              int
	LastReset        time.Time
	LastSeen         int64 // atomic unix nanoseconds
	Stage            int
	Fails            int
	TrustScore       float64
	JA3Hash          string
	Countries        string
	FirstSeen        time.Time
	TotalRequests    int64
	ChallengesServed int
	ChallengesPassed int
	RateLimitHits    int
	CPS              int
	ConnLastReset    time.Time
	IsTrustedProxy   bool
	ActiveConns      int32
}

const ipShardCount = 256

type ipStateShard struct {
	mu sync.RWMutex
	m  map[string]*IPState
}

type IPStateMap struct {
	shards [ipShardCount]*ipStateShard
}

func newIPStateMap() *IPStateMap {
	m := &IPStateMap{}
	for i := 0; i < ipShardCount; i++ {
		m.shards[i] = &ipStateShard{
			m: make(map[string]*IPState, 2048),
		}
	}
	return m
}

func fnv32IP(key string) uint32 {
	hash := uint32(2166136261)
	const prime32 = uint32(16777619)
	for i := 0; i < len(key); i++ {
		hash ^= uint32(key[i])
		hash *= prime32
	}
	return hash
}

func (m *IPStateMap) getShard(ip string) *ipStateShard {
	return m.shards[fnv32IP(ip)%ipShardCount]
}

func (m *IPStateMap) GetOrCreate(ip string, isTrusted bool, now time.Time) *IPState {
	shard := m.getShard(ip)
	shard.mu.RLock()
	state, ok := shard.m[ip]
	shard.mu.RUnlock()

	if ok {
		atomic.StoreInt64(&state.LastSeen, now.UnixNano())
		return state
	}

	shard.mu.Lock()
	defer shard.mu.Unlock()
	if state, ok = shard.m[ip]; ok {
		atomic.StoreInt64(&state.LastSeen, now.UnixNano())
		return state
	}

	state = &IPState{
		LastReset:      now,
		FirstSeen:      now,
		LastSeen:       now.UnixNano(),
		TrustScore:     50,
		IsTrustedProxy: isTrusted,
	}
	shard.m[ip] = state
	return state
}

func (m *IPStateMap) Cleanup(now time.Time, ttl time.Duration) {
	for i := 0; i < ipShardCount; i++ {
		shard := m.shards[i]
		shard.mu.Lock()
		for ip, state := range shard.m {
			lastSeenNs := atomic.LoadInt64(&state.LastSeen)
			if now.UnixNano()-lastSeenNs > int64(ttl) {
				delete(shard.m, ip)
			}
		}
		shard.mu.Unlock()
	}
}

// buildDomainMaps pre-computes O(1) lookup maps from config (called on init and hot-reload)
func buildDomainMaps(cfg *config.Config) (modeMap map[string]string, hostMap map[string]bool) {
	modeMap = make(map[string]string, len(cfg.Domains))
	hostMap = make(map[string]bool, len(cfg.Domains))
	for _, d := range cfg.Domains {
		lower := strings.ToLower(d.Name)
		hostMap[lower] = true
		if d.ProtectionMode != "" {
			modeMap[lower] = d.ProtectionMode
		}
	}
	return
}

// NewPipeline creates a new processing pipeline
func NewPipeline(s *Shield) *Pipeline {
	domainModeMap, validHostMap := buildDomainMaps(s.cfg)
	p := &Pipeline{
		shield:        s,
		cfg:           s.cfg,
		domainModeMap: domainModeMap,
		validHostMap:  validHostMap,
		ipStates:      newIPStateMap(),
		alerts:        NewAlertManager(s.cfg),
		xdpMgr:        NewXDPManager(s.cfg),
	}
	if mesh := cluster.GetMesh(); mesh != nil {
		mesh.SetBanHandler(func(ip string, duration time.Duration) {
			p.BanIPLocal(ip, duration)
		})
		mesh.SetUnbanHandler(func(ip string) {
			if ip == "all" {
				p.banned.Range(func(k, v interface{}) bool {
					p.banned.Delete(k)
					return true
				})
				if p.xdpMgr != nil && p.xdpMgr.Enabled {
					p.xdpMgr.UnbanIP("all")
				}
			} else {
				p.banned.Delete(ip)
				if p.xdpMgr != nil && p.xdpMgr.Enabled {
					p.xdpMgr.UnbanIP(ip)
				}
			}
		})
	}
	return p
}

// GetAlerts returns the alert manager
func (p *Pipeline) GetAlerts() *AlertManager {
	return p.alerts
}

// Process runs a request through the protection pipeline (no fingerprint)
func (p *Pipeline) Process(r *http.Request, ip string) Action {
	return p.ProcessWithFingerprint(r, ip, nil)
}

// resolveDomainMode returns the effective protection mode for the request's domain in O(1) time.
func (p *Pipeline) resolveDomainMode(r *http.Request) string {
	host := strings.ToLower(r.Host)
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		host = host[:idx]
	}
	if mode, ok := p.domainModeMap[host]; ok {
		return mode
	}
	return p.cfg.Protection.Mode
}

// ProcessWithFingerprint runs a request through the pipeline with TLS fingerprint data
func (p *Pipeline) ProcessWithFingerprint(r *http.Request, ip string, fp *fingerprint.ConnectionFingerprint) Action {
	// Layer 0: Check banned
	if p.isBanned(ip) {
		return Action{Type: ActionDrop, Reason: "banned"}
	}

	// Pre-compute: is domain under attack? (cache for entire pipeline — avoid 4x repeated sync.Map lookups)
	isDomainAttack := p.shield.IsDomainUnderAttack(r.Host)

	// Layer 0.05: WAF Rules Deep Inspection (SINGLE pass — no duplicate scan)
	if p.wafEngine != nil && p.cfg.WAF.Enabled {
		if p.degrader == nil || !p.degrader.IsFeatureDisabled("waf_deep_inspect", p.shield.stats.CurrentRPS) {
			wafResult := p.wafEngine.Inspect(r)
			if wafResult.Blocked {
				// Suppress heavy disk log I/O during high RPS attacks (>100 RPS)
				if atomic.LoadInt64(&p.shield.stats.CurrentRPS) < 100 {
					logger.Warn("WAF blocked malicious request", "ip", ip, "rule", wafResult.TopRule, "score", wafResult.Score, "uri", r.RequestURI)
				}
				// If under DDoS attack, push repeated WAF attackers directly to XDP eBPF NIC map
				if isDomainAttack && !p.isTrustedProxy(ip) {
					p.BanIPLocal(ip, p.cfg.Protection.Ban.Duration)
					return Action{Type: ActionDrop, Reason: "waf_attack_xdp:" + wafResult.TopRule}
				}
				if wafResult.Action == "drop" {
					p.BanIPLocal(ip, p.cfg.Protection.Ban.Duration)
					return Action{Type: ActionDrop, Reason: "waf:" + wafResult.TopRule}
				}
				return Action{Type: ActionBlock, Reason: "waf:" + wafResult.TopRule}
			}
		}
	}

	// Layer 0.1: Verified proof cookie (Human user bypass for anti-DDoS rate limits & challenges)
	// REMOVED: Early ActionAllow bypasses rate limits. We now let it fall through and bypass challenges inside determineStageWithFP.

	// Layer 0.2: Static assets & stats endpoints bypass
	if isStaticAsset(r.URL.Path) {
		return Action{Type: ActionAllow, Reason: "static_asset"}
	}

	// Layer 0.5: Emergency mode (uses cached isDomainAttack)
	if isDomainAttack && p.cfg.Protection.Emergency.AutoEnable {
		if !p.isWhitelisted(ip) {
			domainMode := p.resolveDomainMode(r)
			if domainMode == "emergency" || p.cfg.Protection.Mode == "emergency" {
				return Action{Type: ActionBlock, Reason: "emergency_mode"}
			}
		}
	}

	// Layer 1: Connection limit
	count := p.getConnCount(ip)
	if count > p.cfg.Protection.ConnectionLimit.MaxPerIP {
		p.banIP(ip, p.cfg.Protection.Ban.Duration)
		return Action{Type: ActionBlock, Reason: "conn_limit"}
	}

	// Layer 1.5: Request Validation (method, URL length, null bytes, body size)
	if p.validator != nil {
		if valid, reason := p.validator.Validate(r); !valid {
			p.BanIPLocal(ip, 1*time.Hour)
			logger.Warn("Request validation failed", "ip", ip, "reason", reason)
			return Action{Type: ActionBlock, Reason: "validation:" + reason}
		}
	}

	// Layer 2: Basic validation
	if action := p.validateRequest(r, ip); action.Type != ActionAllow {
		return action
	}

	// Layer 2.5: TLS Fingerprint check
	if fp != nil && p.cfg.Fingerprint.JA3.Enabled {
		// Known attack tool fingerprint → immediate block
		if fp.JA3.Known && fp.JA3.TrustScore == 0 {
			// Ban for 6x default duration (e.g. 60m if default is 10m)
			p.BanIPLocal(ip, p.cfg.Protection.Ban.Duration*6)
			logger.Warn("Attack tool detected via JA3",
				"ip", ip, "ja3", fp.JA3.Hash, "browser", fp.JA3.BrowserID)
			return Action{Type: ActionDrop, Reason: "attack_tool_ja3:" + fp.JA3.BrowserID}
		}

		// Very low composite trust → block
		if fp.Composite.Total < 15 {
			// Ban for 3x default duration
			p.BanIPLocal(ip, p.cfg.Protection.Ban.Duration*3)
			logger.Warn("Extremely low trust fingerprint",
				"ip", ip, "trust", fp.Composite.Total, "verdict", fp.Composite.Verdict)
			return Action{Type: ActionBlock, Reason: "fp_malicious"}
		}

		// Trusted browser fingerprint → fast-track (skip challenge ONLY if domain mode is auto/off/monitor and not under attack)
		domainMode := p.resolveDomainMode(r)
		if fp.IsTrusted() && !p.shield.IsDomainUnderAttack(r.Host) && (domainMode == "off" || domainMode == "auto" || domainMode == "monitor" || domainMode == "") {
			return Action{Type: ActionAllow, Reason: "fp_trusted:" + fp.Composite.Verdict}
		}

		// Update IP state with fingerprint trust score
		state := p.getState(ip)
		state.mu.Lock()
		state.TrustScore = fp.Composite.Total
		state.JA3Hash = fp.JA3.Hash
		state.mu.Unlock()
	}

	// Layer 3: Intelligence Layer (GeoIP, IP Reputation, ASN, Threat Feeds)
	// OPTIMIZATION: Disable under high load to save CPU/Network
	if p.intel != nil && (p.degrader == nil || !p.degrader.IsFeatureDisabled("reputation_lookup", p.shield.stats.CurrentRPS)) {
		evalResult := p.intel.Evaluate(ip)
		if evalResult.TrustScore <= 0 {
			// Completely untrusted (blacklisted, geo-blocked, etc.)
			p.BanIPLocal(ip, p.cfg.Protection.Ban.Duration)
			reason := "intel_blocked"
			if len(evalResult.Actions) > 0 {
				reason = "intel:" + evalResult.Actions[0]
			}
			logger.Warn("Intelligence blocked IP", "ip", ip, "trust", evalResult.TrustScore, "actions", evalResult.Actions)
			return Action{Type: ActionBlock, Reason: reason}
		}
		if evalResult.TrustScore < 30 {
			// Very low trust → escalate to challenge
			state := p.getState(ip)
			state.mu.Lock()
			state.TrustScore = evalResult.TrustScore
			state.mu.Unlock()
		}
	}

	// Layer 3.5: Rate Limiting & Anti-DDoS Volumetric Mitigation
	if p.cfg.Protection.RateLimit.Enabled {
		isUnderAttack := isDomainAttack || (p.shield.GetDomainRPS(r.Host) > 200)

		// If under attack or high RPS surge, enforce strict anti-DDoS flood protection for unverified IPs
		// FIX: Only call r.FormValue for POST requests to avoid ParseForm overhead on GET/HEAD
		isVerificationPost := r.Method == "POST" && r.Header.Get("Content-Type") != "" && r.FormValue("challenge_type") != ""
		if isUnderAttack && !p.isWhitelisted(ip) && !isVerificationPost {
			state := p.getState(ip)
			state.mu.Lock()
			nowSec := GetFastCurrentUnixSec()
			lastSec := state.ConnLastReset.Unix()
			if nowSec != lastSec {
				state.RateLimitHits = 1
				state.ConnLastReset = time.Unix(nowSec, 0)
			} else {
				state.RateLimitHits++
			}
			hits := state.RateLimitHits
			state.mu.Unlock()

			limit := p.cfg.Protection.RateLimit.RequestsPerSecond
			if limit <= 0 {
				limit = 50
			}

			if hits > limit {
				atomic.AddInt64(&p.shield.stats.BlockedRequests, 1)
				// Offload flood bot IP directly into NIC eBPF/XDP hardware map!
				if !p.isTrustedProxy(ip) {
					p.BanIPLocal(ip, p.cfg.Protection.Ban.Duration)
				}
				return Action{Type: ActionDrop, Reason: "ddos_flood_xdp"}
			}
		}

		if p.rateLimiter != nil && !p.rateLimiter.Allow(ip) {
			logger.Info("Rate limited", "ip", ip)
			atomic.AddInt64(&p.shield.stats.BlockedRequests, 1)
			state := p.getState(ip)
			state.mu.Lock()
			state.RateLimitHits++
			hits := state.RateLimitHits
			state.mu.Unlock()

			// If they hit the rate limit too many times without a whitelist, they are likely a bot
			if hits > 20 {
				p.BanIPLocal(ip, p.cfg.Protection.Ban.Duration*2)
				return Action{Type: ActionDrop, Reason: "rate_limit_persistent"}
			}

			return Action{Type: ActionRateLimit, Reason: "rate_limited"}
		}
	}

	// Layer 4: Check whitelist (already passed challenge)
	if p.isWhitelisted(ip) {
		return Action{Type: ActionAllow, Reason: "whitelisted"}
	}

	// Layer 5: REMOVED — WAF scan already performed once at Layer 0.05 (eliminates 67% CPU waste from duplicate regex evaluation)

	// Layer 6: Behavior Analysis
	var behaviorVerdict *detection.BehaviorVerdict
	if p.behavior != nil {
		behaviorVerdict = p.behavior.Analyze(ip, r.URL.Path, r.Method, r.UserAgent(), 200)
		if behaviorVerdict.IsBot && behaviorVerdict.Score < 20 {
			// Extreme bot behavior → block
			p.BanIPLocal(ip, p.cfg.Protection.Ban.Duration)
			logger.Warn("Behavior analysis: DDoS bot detected",
				"ip", ip, "score", behaviorVerdict.Score, "profile", behaviorVerdict.Profile)
			return Action{Type: ActionBlock, Reason: "behavior_ddos"}
		}
	}

	// Layer 7: Bot Classification
	if p.botClass != nil && p.cfg.Detection.BotClassifier.Enabled {
		classReq := &detection.ClassifyRequest{
			IP:        ip,
			UserAgent: r.UserAgent(),
			Headers:   extractHeaders(r),
			URL:       r.URL.Path,
			Method:    r.Method,
			Behavior:  behaviorVerdict,
		}
		if fp != nil {
			classReq.Fingerprint = fp
		}
		classResult := p.botClass.Classify(classReq)
		if classResult.IsBot && classResult.Threat == "critical" {
			// Critical threat: 6x default duration
			p.BanIPLocal(ip, p.cfg.Protection.Ban.Duration*6)
			logger.Warn("Bot classified as critical threat",
				"ip", ip, "type", classResult.BotType, "name", classResult.BotName, "confidence", classResult.Confidence)
			return Action{Type: ActionDrop, Reason: "bot:" + classResult.BotType}
		}
		if classResult.IsBot && classResult.Threat == "high" && !p.hasValidProof(r, ip) {
			diff := p.cfg.Protection.Challenge.PowDifficulty + 1
			if diff > 4 {
				diff = 4
			}
			return Action{Type: ActionChallenge, Reason: "bot_suspicious", Stage: 2, Difficulty: diff}
		}
	}

	// Layer 8: Session Tracking
	if p.detEngine != nil && p.cfg.Detection.SessionTracking.Enabled {
		session := p.detEngine.TrackSession(ip, r.URL.Path, r.UserAgent())
		if session != nil && session.Suspicious {
			logger.Info("Suspicious session detected", "ip", ip, "trust", session.TrustScore, "requests", session.Requests)
		}
	}

	// Layer 9: Rate limiting via detection engine (adaptive token bucket)
	if p.detEngine != nil && p.cfg.Protection.RateLimit.Enabled {
		if p.detEngine.CheckRateLimit(ip) && !p.hasValidProof(r, ip) {
			return Action{Type: ActionChallenge, Reason: "det_rate_limited", Stage: 1, Difficulty: p.cfg.Protection.Challenge.PowDifficulty}
		}
	}

	// Layer 10: Determine challenge stage (fingerprint-aware + adaptive learner)
	state := p.getState(ip)
	p.updateRPS(state)

	domainMode := p.resolveDomainMode(r)
	stage := p.determineStageWithFP(state, ip, r, fp, domainMode, isDomainAttack)

	// Stage 4 triggers an immediate TCP Drop (no HTTP response sent) to save maximum network bandwidth/CPU.
	if stage == 4 {
		if !p.isTrustedProxy(ip) {
			p.BanIPLocal(ip, p.cfg.Protection.Ban.Duration)
		}
		return Action{Type: ActionDrop, Reason: "auto_l7_drop"}
	}

	if stage > 0 {
		difficulty := p.cfg.Protection.Challenge.PowDifficulty
		if p.cfg.Protection.Challenge.PowAdaptive {
			if state.RPS > 50 {
				difficulty += 1
			}
			if state.RPS > 100 {
				difficulty += 2
			}
			// Fingerprint-based difficulty adjustment
			if fp != nil && fp.Composite.Total < 40 {
				difficulty += 1
			}
		}
		if difficulty > 4 {
			difficulty = 4
		}

		// Adaptive learner difficulty adjustment
		if p.adaptive != nil {
			adDecision := p.adaptive.GetDecision(float64(state.RPS))
			if adDecision.ChallengeLevel > stage {
				stage = adDecision.ChallengeLevel
			}
		}

		// Cap max difficulty to prevent browser hangs
		if difficulty > 6 {
			difficulty = 6
		}

		// Pre-computed stage name string (zero allocation)
		reason := "stage_0"
		if stage >= 0 && stage < len(stageNames) {
			reason = stageNames[stage]
		}
		return Action{
			Type:       ActionChallenge,
			Reason:     reason,
			Stage:      stage,
			Difficulty: difficulty,
		}
	}

	return Action{Type: ActionAllow, Reason: "clean"}
}

// extractHeaders converts http.Header to map[string]string for bot classifier
func extractHeaders(r *http.Request) map[string]string {
	headers := make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}
	return headers
}

// validateRequest performs basic request validation
func (p *Pipeline) validateRequest(r *http.Request, ip string) Action {
	if !p.validHost(r) {
		return Action{Type: ActionBlock, Reason: "invalid_host"}
	}
	if p.isBadUA(r) {
		return Action{Type: ActionBlock, Reason: "bad_ua"}
	}
	return Action{Type: ActionAllow}
}

// validHost checks if the host header matches configured domains using pre-built O(1) map
func (p *Pipeline) validHost(r *http.Request) bool {
	host := strings.ToLower(r.Host)
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		host = host[:idx]
	}
	// O(1) lookup instead of O(N) domain scan
	if p.validHostMap[host] {
		return true
	}
	// Fallback: substring match for wildcard domains
	for domain := range p.validHostMap {
		if strings.Contains(host, domain) {
			return true
		}
	}
	return false
}

// isBadUA detects known bot/tool user agents using pre-built set (zero allocation)
func (p *Pipeline) isBadUA(r *http.Request) bool {
	ua := r.UserAgent()
	if ua == "" {
		return true
	}
	uaLower := strings.ToLower(ua)
	for keyword := range badUASet {
		if strings.Contains(uaLower, keyword) {
			return true
		}
	}
	return false
}

// determineStageWithFP determines challenge stage with fingerprint awareness
func (p *Pipeline) determineStageWithFP(state *IPState, ip string, r *http.Request, fp *fingerprint.ConnectionFingerprint, domainMode string, isDomainAttack bool) int {
	mode := domainMode
	isDomainUnderAttack := isDomainAttack

	switch mode {
	case "off", "monitor":
		return 0
	case "silent":
		if p.hasValidProof(r, ip) {
			return 0
		}
		return 3
	case "challenge":
		if p.hasValidProof(r, ip) {
			return 0
		}
		return 1
	case "captcha":
		if p.hasValidProof(r, ip) {
			return 0
		}
		return 2
	case "emergency":
		if p.hasValidProof(r, ip) {
			return 0
		}
		return 4 // Drop all unauthenticated traffic
	case "under_attack":
		if p.hasValidProof(r, ip) {
			return 0
		}
		return 2 // Strict PoW challenge for all unverified traffic
	case "auto":
		if p.hasValidProof(r, ip) {
			return 0
		}

		limit := p.cfg.Protection.RateLimit.RequestsPerSecond
		systemRPS := atomic.LoadInt64(&p.shield.stats.CurrentRPS)
		threshold := int64(p.cfg.Protection.Emergency.RPSThreshold)
		if threshold <= 0 {
			threshold = 50
		}

		// 1. Extreme System Load (DDoS Tsunami)
		if systemRPS > threshold*2 {
			if state.RPS > limit*2 {
				return 4 // Drop instantly at kernel layer
			}
			return 2 // Turnstile Captcha
		}

		// 2. Aggregate DDoS Attack Active -> Enforce JS PoW / CAPTCHA on ALL unverified traffic!
		if isDomainUnderAttack || systemRPS > threshold {
			if state.RPS > limit*2 {
				return 2 // Captcha for high RPS surge
			}
			return 1 // JS PoW Challenge for ALL unverified traffic (stops distributed botnets!)
		}

		// 3. Smart Per-IP Behavioral Analysis under normal baseline
		if fp != nil {
			switch {
			case fp.Composite.Total >= 60: // High trust: known browsers
				if state.RPS > limit*4 {
					return 2 // Extremely high RPS -> Captcha
				}
				if state.RPS > limit*2 {
					return 1 // High RPS -> JS Challenge
				}
				return 0

			case fp.Composite.Total >= 30: // Medium trust: Incognito / Likely legit
				if state.RPS > limit*3 {
					return 2 // Very high RPS -> Captcha
				}
				if state.RPS > limit*3/2 {
					return 1 // Moderate-High RPS -> JS Challenge
				}
				return 0

			default: // Low trust: Score < 30 (Bots / Suspicious)
				if state.RPS > limit {
					return 1 // Moderate RPS from suspicious source -> JS Challenge
				}
				return 0
			}
		}

		// Fallback (no fingerprinting available)
		if state.RPS > limit*2 {
			return 2
		}
		if state.RPS > limit {
			return 1
		}
		return 0 // Truly seamless for first-time visitors when system is healthy
	}
	return 0
}

// hasValidProof checks if the request has a valid PoW proof cookie or dynamic whitelist
func (p *Pipeline) hasValidProof(r *http.Request, ip string) bool {
	if p.hasDynamicWhitelist(ip) {
		return true
	}
	if p.shield != nil && p.shield.challMgr != nil {
		return p.shield.challMgr.VerifyProof(r, ip)
	}
	return false
}

// getState gets or creates IP state
func (p *Pipeline) getState(ip string) *IPState {
	return p.ipStates.GetOrCreate(ip, p.checkIsTrustedProxy(ip), time.Now())
}

// updateRPS updates the per-IP RPS counter using cached timestamp (zero syscall)
func (p *Pipeline) updateRPS(s *IPState) {
	s.mu.Lock()
	nowSec := GetFastCurrentUnixSec()
	s.TotalRequests++
	if nowSec != s.LastReset.Unix() {
		s.RPS = 1
		s.LastReset = time.Unix(nowSec, 0)
	} else {
		s.RPS++
	}
	s.mu.Unlock()
}

// getConnCount gets the active connection count for an IP
func (p *Pipeline) getConnCount(ip string) int {
	state := p.getState(ip)
	return int(atomic.LoadInt32(&state.ActiveConns))
}

// IncrementConnCount increments the active connection count for an IP
func (p *Pipeline) IncrementConnCount(ip string) int {
	state := p.getState(ip)
	return int(atomic.AddInt32(&state.ActiveConns, 1))
}

// DecrementConnCount decrements the active connection count for an IP
func (p *Pipeline) DecrementConnCount(ip string) int {
	state := p.getState(ip)
	val := atomic.AddInt32(&state.ActiveConns, -1)
	if val < 0 {
		atomic.StoreInt32(&state.ActiveConns, 0)
		return 0
	}
	return int(val)
}

// isBanned checks if an IP is banned
func (p *Pipeline) isBanned(ip string) bool {
	if p.isTrustedProxy(ip) || p.isWhitelisted(ip) {
		return false
	}
	v, ok := p.banned.Load(ip)
	if !ok {
		return false
	}
	expiry := v.(time.Time)
	if time.Now().After(expiry) {
		p.banned.Delete(ip)
		return false
	}
	return true
}

var defaultCloudflareCIDRs = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

var defaultCloudflareNets []*net.IPNet

func init() {
	for _, cidr := range defaultCloudflareCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			defaultCloudflareNets = append(defaultCloudflareNets, network)
		}
	}
}

// isTrustedProxy checks if an IP belongs to trusted proxies (e.g. Cloudflare) using cached state
func (p *Pipeline) isTrustedProxy(ipStr string) bool {
	if ipStr == "" {
		return false
	}
	return p.getState(ipStr).IsTrustedProxy
}

// checkIsTrustedProxy checks if an IP belongs to trusted proxies by scanning CIDRs
func (p *Pipeline) checkIsTrustedProxy(ipStr string) bool {
	if ipStr == "" {
		return false
	}
	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		return false
	}

	// Always trust Cloudflare proxy IPs
	for _, netObj := range defaultCloudflareNets {
		if netObj.Contains(parsedIP) {
			return true
		}
	}

	if p.cfg != nil {
		for _, trusted := range p.cfg.Protection.TrustedProxies {
			if trusted == ipStr {
				return true
			}
			_, cidr, err := net.ParseCIDR(trusted)
			if err == nil && cidr.Contains(parsedIP) {
				return true
			}
		}
	}
	return false
}

// isWhitelisted checks if an IP is whitelisted (static config only)
func (p *Pipeline) isWhitelisted(ip string) bool {
	// Check static whitelist from config
	for _, w := range p.cfg.Protection.WhitelistIPs {
		if ip == w {
			return true
		}
	}
	return false
}

// hasDynamicWhitelist checks if an IP recently passed a challenge
func (p *Pipeline) hasDynamicWhitelist(ip string) bool {
	v, ok := p.whitelist.Load(ip)
	if !ok {
		return false
	}
	expiry := v.(time.Time)
	if time.Now().After(expiry) {
		p.whitelist.Delete(ip)
		return false
	}
	return true
}

// CheckConnRate checks if an IP is opening connections too fast (CPS)
func (p *Pipeline) CheckConnRate(ip string) bool {
	if p.isTrustedProxy(ip) || p.isWhitelisted(ip) {
		return true
	}
	state := p.getState(ip)
	state.mu.Lock()
	defer state.mu.Unlock()

	now := time.Now()
	if now.Sub(state.ConnLastReset) >= time.Second {
		state.CPS = 1
		state.ConnLastReset = now
	} else {
		state.CPS++
	}

	// Connection Per Second (CPS) limit
	// Allow 100 CPS for modern multi-socket parallel browser connections
	if state.CPS > 100 {
		return false
	}
	return true
}

// BanIPLocal bans an IP locally, pushes to eBPF/XDP kernel map, and broadcasts to cluster mesh
func (p *Pipeline) BanIPLocal(ip string, duration time.Duration) {
	if ip == "" || p.isTrustedProxy(ip) || p.checkIsTrustedProxy(ip) || p.isWhitelisted(ip) {
		return // CRITICAL: NEVER ban Cloudflare proxy IPs or whitelisted IPs in eBPF/iptables!
	}
	p.banIP(ip, duration)

	// Broadcast to cluster mesh
	if mesh := cluster.GetMesh(); mesh != nil {
		mesh.BroadcastBan(ip, duration)
	}
}

// BanIPRemote is called by the Gossip network when another node bans an IP
func (p *Pipeline) BanIPRemote(ip string, duration time.Duration) {
	if p.isTrustedProxy(ip) || p.isWhitelisted(ip) {
		return
	}
	p.banIP(ip, duration)
}

// banIP bans an IP for a duration with high-performance kernel-level blocking
func (p *Pipeline) banIP(ip string, duration time.Duration) {
	if p.isTrustedProxy(ip) || p.isWhitelisted(ip) {
		logger.Info("Refusing to ban trusted proxy or whitelisted IP", "ip", ip)
		return
	}
	if _, already := p.banned.LoadOrStore(ip, time.Now().Add(duration)); !already {
		atomic.AddInt64(&p.shield.stats.BannedIPs, 1)
	} else {
		p.banned.Store(ip, time.Now().Add(duration))
	}
	logger.Info("IP banned", "ip", ip, "duration", duration)

	// 1. Unbeatable Hardware-level Drop (XDP / eBPF) - Only for direct non-proxy IPs
	if p.xdpMgr != nil && p.xdpMgr.Enabled && !p.isTrustedProxy(ip) {
		if err := p.xdpMgr.BanIP(ip); err != nil {
			logger.Warn("XDP Map insertion failed", "ip", ip, "err", err)
		}
	}

	if p.cfg.Protection.Ban.UseIptables && !p.isTrustedProxy(ip) {
		timeoutSec := int(duration.Seconds())
		go func() {
			cmd := exec.Command("ipset", "add", "mango_bans", ip, "timeout", fmt.Sprintf("%d", timeoutSec), "-exist")
			if err := cmd.Run(); err != nil {
				logger.Debug("IPSet ban skipped or failed", "ip", ip, "error", err)
			}
		}()
	}
}

// WhitelistIP whitelists an IP for a duration
func (p *Pipeline) WhitelistIP(ip string, duration time.Duration) {
	p.whitelist.Store(ip, time.Now().Add(duration))
}

// UnbanIP unbans a specific IP address
func (p *Pipeline) UnbanIP(ip string) {
	p.banned.Delete(ip)
	if p.xdpMgr != nil && p.xdpMgr.Enabled {
		p.xdpMgr.UnbanIP(ip)
	}
	if mesh := cluster.GetMesh(); mesh != nil {
		mesh.BroadcastUnban(ip)
	}
	logger.Info("IP manually unbanned", "ip", ip)
}

// GetBannedIPsList returns the current list of banned IPs with expiry times
func (p *Pipeline) GetBannedIPsList() []string {
	now := time.Now()
	var result []string
	p.banned.Range(func(key, value interface{}) bool {
		expiry := value.(time.Time)
		if now.Before(expiry) {
			ttl := int64(expiry.Sub(now).Seconds())
			result = append(result, fmt.Sprintf("%s|%s|%d", key.(string), expiry.Format("2006-01-02 15:04:05"), ttl))
		} else {
			p.banned.Delete(key)
		}
		return true
	})
	return result
}

// UnbanAllIPs clears all banned IPs from memory and eBPF
func (p *Pipeline) UnbanAllIPs() {
	p.banned.Range(func(key, value interface{}) bool {
		ipStr := key.(string)
		p.banned.Delete(key)
		if p.xdpMgr != nil && p.xdpMgr.Enabled {
			p.xdpMgr.UnbanIP(ipStr)
		}
		return true
	})
	if mesh := cluster.GetMesh(); mesh != nil {
		mesh.BroadcastUnban("all")
	}
	atomic.StoreInt64(&p.shield.stats.BannedIPs, 0)
	logger.Info("All IPs unbanned")
}

// Cleanup removes expired entries
func (p *Pipeline) Cleanup() {
	now := time.Now()
	p.banned.Range(func(key, value interface{}) bool {
		if now.After(value.(time.Time)) {
			ipStr := key.(string)
			p.banned.Delete(key)
			atomic.AddInt64(&p.shield.stats.BannedIPs, -1)
			if p.xdpMgr != nil && p.xdpMgr.Enabled {
				p.xdpMgr.UnbanIP(ipStr)
			}
		}
		return true
	})
	p.whitelist.Range(func(key, value interface{}) bool {
		if now.After(value.(time.Time)) {
			p.whitelist.Delete(key)
		}
		return true
	})

	p.ipStates.Cleanup(now, 10*time.Minute)
}

func isStaticAsset(path string) bool {
	// Whitelist all /api/ endpoints (login, admin authentication, stats, etc.) so API calls NEVER return HTML Captchas
	if strings.HasPrefix(path, "/api/") || path == "/api" {
		return true
	}
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot":
		return true
	}
	return path == "/favicon.ico"
}
